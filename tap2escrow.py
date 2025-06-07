import random
from io import BytesIO
import util
import hashlib
import math
import time
from pympler import asizeof
from test_framework.key import (
    generate_key_pair, generate_bip340_key_pair, ECKey, modinv, ECPubKey,
    int_or_bytes, jacobi_symbol, generate_schnorr_nonce_and_point,
    SECP256K1_FIELD_SIZE, SECP256K1_G, SECP256K1, SECP256K1_ORDER,
    TaggedHash, verify_ring_signature,generate_schnorr_nonce
)
from test_framework.messages import sha256, CTransaction, COutPoint, CTxIn, CTxOut, CTxInWitness
from test_framework.script import *
from test_framework.address import program_to_witness
from util import generate_keys, p2tr_locking, twist_elgamal_encrypt, divide_256bit_to_32bit_parts, combine_32bit_parts_to_256bit
import configparser
import os


def main():

    # Generate a random scalar k
    k = random.randint(1, SECP256K1_ORDER)

    # Calculate new generator H = k * G
    H = SECP256K1.mul([(SECP256K1_G, k)])
    print(f"H is as follows: {H}")

    # generate keys
    sk_y,Y,t,T,sk_A,PK_A,sk_R,PK_R = generate_keys(H)

    segwit_address, tapscript, taptweak, control_map, tapscript_multisig = p2tr_locking(Y, PK_R)

    # setup test wrapper
    test = util.TestWrapper()
    test.setup()
    test.nodes[0].generate(101)

    # Send funds to taproot output.
    txid = test.nodes[0].sendtoaddress(address=segwit_address, amount=5, fee_rate=25)

    # Deserialize wallet transaction.
    tx = CTransaction()
    tx_hex = test.nodes[0].getrawtransaction(txid)
    tx.deserialize(BytesIO(bytes.fromhex(tx_hex)))
    tx.rehash()

    # The wallet randomizes the change output index for privacy
    # Loop through the outputs and return the first where the scriptPubKey matches the segwit v1 output
    output_index, output = next(out for out in enumerate(tx.vout) if out[1].scriptPubKey == tapscript)
    output_value = output.nValue

    tx_information = test.nodes[0].decoderawtransaction(tx.serialize().hex())
    print(f"Transaction size: {tx_information['size']}")
    print(f"Transaction vsize: {tx_information['vsize']}")
    print(f"Transaction Weight: {tx_information['weight']}")

    # Create Spending Tx
    spending_tx = CTransaction()
    spending_tx.nVersion = 1
    spending_tx.nLockTime = 0
    outpoint = COutPoint(tx.sha256, output_index)
    spending_tx_in = CTxIn(outpoint = outpoint)
    spending_tx.vin = [spending_tx_in]

    # Generate new Bitcoin Core wallet address
    # dest_addr = test.nodes[0].getnewaddress(address_type="bech32")
    # scriptpubkey = bytes.fromhex(test.nodes[0].getaddressinfo(dest_addr)['scriptPubKey'])
    scriptpubkey = PK_R.get_bytes()
    # Determine minimum fee required for mempool acceptance
    min_fee = int(test.nodes[0].getmempoolinfo()['mempoolminfee'] * 100000000)

    # Complete output which returns funds to Bitcoin Core wallet
    dest_output = CTxOut(nValue=output_value - min_fee, scriptPubKey=scriptpubkey)
    spending_tx.vout = [dest_output]

    sighash = TaprootSignatureHash(spending_tx, [output], SIGHASH_ALL_TAPROOT, 0, scriptpath=True, script=tapscript_multisig.script)
    witness_elements = []
    # Adaptor Signature
    R_adap, adaptor_signature = sk_y.create_adaptor_signature(T, sighash)
    print(f"adaptor signature: {adaptor_signature}")
    print(f"R_adap: {R_adap}")

    # Adaptor Signature Verification
    assert util.verify_adaptor_signature(R_adap, T, Y, sighash, adaptor_signature) == True

    adaptor_parts = divide_256bit_to_32bit_parts(t.secret)
    enc_adaptor_list = [0]*8
    beta_list = [0]*8
    for i in range(0, 8):
        beta_i = random.randrange(1, SECP256K1_ORDER)
        beta_list[i] = beta_i
        u_i, v_i = twist_elgamal_encrypt(beta_i, adaptor_parts[i], PK_A, H)
        enc_adaptor_list[i] = ((u_i, v_i))

    TT = None
    for i, u in enumerate(adaptor_parts):
        scalar = 2**(32*(7 - i))
        scaled_beta = (scalar*u) % SECP256K1_ORDER
        if TT is None:
            TT = scaled_beta
        else:
            TT = (TT + scaled_beta) % SECP256K1_ORDER

    # Proof of correct twisted Elgamal encryption
    #U=\sum 2^{i-1}.u_i
    U = None
    u_list = [pair[0] for pair in enc_adaptor_list]
    for i, u in enumerate(u_list):
        scalar = 2**(32*(7 - i))
        scaled_point = SECP256K1.mul([(u, scalar)])
        if U is None:
            U = scaled_point
        else:
            U = SECP256K1.affine(SECP256K1.add(U,scaled_point))

    # Proof of correct twisted Elgamal encryption
    #U=\sum 2^{i-1}.u_i
    V = None
    u_list = [pair[1] for pair in enc_adaptor_list]
    for i, u in enumerate(u_list):
        scalar = 2**(32*(7 - i))
        scaled_point = SECP256K1.mul([(u, scalar)])
        if V is None:
            V = scaled_point
        else:
            V = SECP256K1.affine(SECP256K1.add(V,scaled_point))

    # Proof of correct twisted Elgamal encryption
    #U=\sum 2^{i-1}.u_i
    beta = None
    for i, u in enumerate(beta_list):
        scalar = 2**(32*(7 - i))
        scaled_beta = (scalar*u) % SECP256K1_ORDER
        if beta is None:
            beta = scaled_beta
        else:
            beta = (beta + scaled_beta) % SECP256K1_ORDER

    e, z1, z2 = util.prove_correct_twisted_elgamal_encryption(H, PK_A, t, U, beta)
    # assert util.verify_correct_twisted_elgamal_encryption(T, H, PK_A, U, V, e, z1, z2) == True

    M_list = util.twisted_elgamal_decrypt(enc_adaptor_list, sk_A)
    print(f"M_list: {M_list}")

    # recovered_number = util.run_shanks_algorithm(M_list)
    # print(f"Recovered 256-bit number: {recovered_number}")

    # CACHE_PATH = "secp256k1_babysteps_2_16.pkl"
    config = configparser.ConfigParser()
    configfile = os.path.abspath(os.path.dirname(__file__)) + "/config.ini"
    config.read_file(open(configfile, encoding="utf8"))
    CACHE_PATH = config["path"]["CACHE_PATH"]
    try:
        lookup = util.load_lookup_from_disk(CACHE_PATH)
    except FileNotFoundError:
        print(f"Cache file not found. Building new lookup table...")
        # lookup = util.build_baby_step_lookup(SECP256K1_G, bits=32, tunning=0)
        lookup = util.build_baby_step_lookup(SECP256K1_G, bits=32, tunning=4)
        util.save_lookup_to_disk(lookup, CACHE_PATH)

    start = time.process_time()    # Recover x using the lookup table
    recovered_segments = []
    for i, pt in enumerate(M_list):
        # scalar = util.recover_discrete_log(pt, SECP256K1_G, lookup, bits=32, tunning=0)
        scalar = util.recover_discrete_log(pt, SECP256K1_G, lookup, bits=32, tunning=4)
        recovered_segments.append(scalar)

    # recombine to 256-bit number
    recovered_number = 0
    for i, seg in enumerate(recovered_segments):
        recovered_number |= seg << (32 * (7 - i))
    end = time.process_time()
    print(f"Execution time: {end - start:.4f} seconds")
    print(f"Recovered 256-bit number: {recovered_number}")

    # Adapt Signature
    s = int.from_bytes(adaptor_signature, 'big')
    complete_sign_using_adaptor = ((s + recovered_number) % SECP256K1_ORDER).to_bytes(32, 'big')
    print(f"complete_sign_using_adaptor : {complete_sign_using_adaptor}")
    
    # Compute R+T
    R_T = SECP256K1.affine(SECP256K1.add(R_adap, T))
    R_x_bytes = R_T[0].to_bytes(32, 'big')

    # Generate sig = R_x|sign
    y_sign = R_x_bytes + complete_sign_using_adaptor
    print(f"verify: {Y.verify_schnorr(y_sign, sighash)}")

     # Add signatures to the witness
    sigs = []
    sigs.append(y_sign)
    sigs.append(sk_R.sign_schnorr(sighash))

    # Add witness to transaction
    # reversed_sigs = list(reversed(sigs))
    # print("reversed_sigs: ",reversed_sigs)
    witness_elements = []
    for sig in sigs:
        witness_elements.append(sig)
    witness_elements.append(tapscript_multisig.script)
    witness_elements.append(control_map[tapscript_multisig.script])

    for op in tapscript_multisig.script:
        print(op.hex()) if isinstance(op, bytes) else print(op)
    print(f"{control_map[tapscript_multisig.script].hex()}\n")

    spending_tx.wit.vtxinwit = []
    spending_tx.wit.vtxinwit.append(CTxInWitness(witness_elements))
    spending_tx_str = spending_tx.serialize().hex()
    tx_information = test.nodes[0].decoderawtransaction(spending_tx.serialize().hex())
    print(f"Spending Transaction: {tx_information}")
    print(f"Transaction Id: {tx_information['txid']}")
    print(f"Transaction size: {tx_information['size']}")
    print(f"Transaction vsize: {tx_information['vsize']}")
    print(f"Transaction Weight: {tx_information['weight']}")

    # Test mempool acceptance
    test_status = test.nodes[0].test_transaction(spending_tx)
    print(f"Spending Transaction acceptance status is {test_status}")

    # # tapscript_delay = TapLeaf().construct_pk_delay(Y, 10)
    # # 290bc6192c5e28f63640b0ee7ebfac5c0f9ffc8ce49f1f5a81b7b3b151c1edb2
    # # OP_CHECKSIG
    # # OP_VERIFY
    # # 0a
    # # OP_CHECKSEQUENCEVERIFY

    #  # Add signatures to the witness
    # # sigs = []
    # # sigs.append(y_sign)
    # # Add witness to transaction
    # # reversed_sigs = list(reversed(sigs))
    # # print("reversed_sigs: ",reversed_sigs)
    # witness_elements = []

    # witness_elements.append(y_sign)
    # witness_elements.append(tapscript_delay.script)
    # witness_elements.append(control_map[tapscript_delay.script])

    # for op in tapscript_delay.script:
    #     print(op.hex()) if isinstance(op, bytes) else print(op)
    # print(f"{control_map[tapscript_delay.script].hex()}\n")

    # spending_tx.wit.vtxinwit = []

    # spending_tx.wit.vtxinwit.append(CTxInWitness(witness_elements))
    # spending_tx_str = spending_tx.serialize().hex()
    # tx_information = test.nodes[0].decoderawtransaction(spending_tx.serialize().hex())
    # # print(f"Transaction Id: {tx_information['txid']}")
    # print(f"Spending Transaction: {tx_information}")
    # print(f"Transaction Id: {tx_information['txid']}")
    # print(f"Transaction size: {tx_information['size']}")
    # print(f"Transaction vsize: {tx_information['vsize']}")
    # print(f"Transaction Weight: {tx_information['weight']}")

    # # Test mempool acceptance
    # test_status = test.nodes[0].test_transaction(spending_tx)
    # print(f"Spending Transaction acceptance status is {test_status}")


    test.shutdown()

if __name__ == "__main__":
    print("Starting...")
    main()
