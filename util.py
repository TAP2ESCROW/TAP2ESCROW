import argparse
import configparser
from io import BytesIO
import os
import time
import math
from pympler import asizeof
import psutil
import random
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.key import (
    generate_key_pair, generate_bip340_key_pair, ECKey, modinv, ECPubKey,
    int_or_bytes, jacobi_symbol, generate_schnorr_nonce_and_point,
    SECP256K1_FIELD_SIZE, SECP256K1_G, SECP256K1, SECP256K1_ORDER,
    TaggedHash, verify_ring_signature,generate_schnorr_nonce
)
from test_framework.script import *
from test_framework.address import program_to_witness
from tqdm import tqdm 
import pickle



# Read configuration from config.ini
config = configparser.ConfigParser()
configfile = os.path.abspath(os.path.dirname(__file__)) + "/config.ini"
config.read_file(open(configfile, encoding="utf8"))

SOURCE_DIRECTORY = config["path"]["SOURCE_DIRECTORY"]

assert not SOURCE_DIRECTORY == '', 'SOURCE_DIRECTORY not configured! Edit config.ini to configure SOURCE_DIRECTORY.'

print("Source directory configured as {}".format(SOURCE_DIRECTORY))

class TestWrapper:
    """Singleton TestWrapper class.

    This wraps the actual TestWrapper class to ensure that users only ever
    instantiate a single TestWrapper."""

    class __TestWrapper(BitcoinTestFramework):
        """Wrapper Class for BitcoinTestFramework.

        Provides the BitcoinTestFramework rpc & daemon process management
        functionality to external python projects."""

        def set_test_params(self):
            # This can be overriden in setup() parameter.
            self.num_nodes = 1

        def run_test(self):
            pass

        def setup(self,
                  bitcoind=os.path.abspath(SOURCE_DIRECTORY + "/src/bitcoind"),
                  bitcoincli=None,
                  setup_clean_chain=True,
                  num_nodes=1,
                  network_thread=None,
                  rpc_timeout=60,
                  supports_cli=False,
                  bind_to_localhost_only=True,
                  nocleanup=False,
                  noshutdown=False,
                  cachedir=os.path.abspath(SOURCE_DIRECTORY + "/test/cache"),
                  tmpdir=None,
                  loglevel='INFO',
                  trace_rpc=False,
                  port_seed=os.getpid(),
                  coveragedir=None,
                  configfile=os.path.abspath(SOURCE_DIRECTORY + "/test/config.ini"),
                  pdbonfailure=False,
                  usecli=False,
                  perf=False,
                  randomseed=None):

            if self.running:
                print("TestWrapper is already running!")
                return

            # Check whether there are any bitcoind processes running on the system
            for p in [proc for proc in psutil.process_iter() if 'bitcoin' in proc.name()]:
                if p.exe().split('/')[-1] == 'bitcoind':
                    print("bitcoind processes are already running on this system. Please shutdown all bitcoind processes!")
                    return

            self.setup_clean_chain = setup_clean_chain
            self.num_nodes = num_nodes
            self.network_thread = network_thread
            self.rpc_timeout = rpc_timeout
            self.supports_cli = supports_cli
            self.bind_to_localhost_only = bind_to_localhost_only

            self.options = argparse.Namespace
            self.options.nocleanup = nocleanup
            self.options.noshutdown = noshutdown
            self.options.cachedir = cachedir
            self.options.tmpdir = tmpdir
            self.options.loglevel = loglevel
            self.options.trace_rpc = trace_rpc
            self.options.port_seed = port_seed
            self.options.coveragedir = coveragedir
            self.options.configfile = configfile
            self.options.pdbonfailure = pdbonfailure
            self.options.usecli = usecli
            self.options.perf = perf
            self.options.randomseed = randomseed

            self.options.bitcoind = bitcoind
            self.options.bitcoincli = bitcoincli

            super().setup()

            # Add notebook-specific methods
            for node in self.nodes:
                node.generate_and_send_coins = generate_and_send_coins.__get__(node)
                node.test_transaction = test_transaction.__get__(node)
            self.running = True

        def create_spending_transaction(self, txid, version=1, nSequence=0):
            """Construct a CTransaction object that spends the first ouput from txid."""
            # Construct transaction
            spending_tx = CTransaction()

            # Populate the transaction version
            spending_tx.nVersion = version

            # Populate the locktime
            spending_tx.nLockTime = 0

            # Populate the transaction inputs
            outpoint = COutPoint(int(txid, 16), 0)
            spending_tx_in = CTxIn(outpoint=outpoint, nSequence=nSequence)
            spending_tx.vin = [spending_tx_in]

            # Generate new Bitcoin Core wallet address
            dest_addr = self.nodes[0].getnewaddress(address_type="bech32")
            scriptpubkey = bytes.fromhex(self.nodes[0].getaddressinfo(dest_addr)['scriptPubKey'])

            # Complete output which returns 0.5 BTC to Bitcoin Core wallet
            amount_sat = int(0.5 * 100_000_000)
            dest_output = CTxOut(nValue=amount_sat, scriptPubKey=scriptpubkey)
            spending_tx.vout = [dest_output]

            return spending_tx

        def shutdown(self):
            if not self.running:
                print("TestWrapper is not running!")
            else:
                super().shutdown()
                self.running = False

    instance = None

    def __new__(cls):
        if not TestWrapper.instance:
            TestWrapper.instance = TestWrapper.__TestWrapper()
            TestWrapper.instance.running = False
        return TestWrapper.instance

    def __getattr__(self, name):
        return getattr(self.instance, name)

    def __setattr__(self, name):
        return setattr(self.instance, name)

def generate_and_send_coins(node, address):
    """Generate blocks on node and then send 1 BTC to address.

    No change output is added to the transaction.
    Return a CTransaction object."""
    version = node.getnetworkinfo()['subversion']
    print("\nClient version is {}\n".format(version))

    # Generate 101 blocks and send reward to bech32 address
    reward_address = node.getnewaddress(address_type="bech32")
    node.generatetoaddress(101, reward_address)
    balance = node.getbalance()
    print("Balance: {}\n".format(balance))

    assert balance > 1

    unspent_txid = node.listunspent(1)[-1]["txid"]
    inputs = [{"txid": unspent_txid, "vout": 0}]

    # Create a raw transaction sending 1 BTC to the address, then sign and send it.
    # We won't create a change output, so maxfeerate must be set to 0
    # to allow any fee rate.
    tx_hex = node.createrawtransaction(inputs=inputs, outputs=[{address: 1}])

    res = node.signrawtransactionwithwallet(hexstring=tx_hex)

    tx_hex = res["hex"]
    assert res["complete"]
    assert 'errors' not in res

    txid = node.sendrawtransaction(hexstring=tx_hex, maxfeerate=0)

    tx_hex = node.getrawtransaction(txid)

    # Reconstruct wallet transaction locally
    tx = CTransaction()
    tx.deserialize(BytesIO(bytes.fromhex(tx_hex)))
    tx.rehash()

    return tx

def test_transaction(node, tx):
    tx_str = tx.serialize().hex()
    ret = node.testmempoolaccept(rawtxs=[tx_str], maxfeerate=0)[0]
    print(ret)
    return ret['allowed']

def propmt_musig_options():
    print("Please select one of the following options")
    print("Please enter 1 for Key Path spending")
    print("Please enter 2 for Script Path spending")
    choice = int(input("Input: "))
    print("")
    if choice > 2 or choice < 1:
        raise Exception("Invalid Choice")
    return choice

def generate_keys(H):
    # Threshold Pub Key
    sk_y,Y = generate_bip340_key_pair()

    # Threshold Adaptor point
    t, T = generate_schnorr_nonce_and_point()

    # Adjudicator Key Generation
    sk_A = random.randrange(1, SECP256K1_ORDER)
    PK_A = SECP256K1.affine(SECP256K1.mul([(H, modinv(sk_A, SECP256K1_ORDER))]))

    # Receiver Pub Key
    sk_R, PK_R = generate_bip340_key_pair()

    # print(f"Threshold Keys: {sk_y}, {Y}")
    # print(f"Threshold Adaptor point: {t}, {T}")
    # print(f"Adjudicator Keys: {sk_A}, {PK_A}")
    # print(f"Receiver Pub Key: {PK_R}")

    return sk_y,Y,t,T,sk_A,PK_A,sk_R,PK_R

def p2tr_locking(Y, PK_R):
    # generate NUMS key
    x,y,z = SECP256K1.lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)
    A = ECPubKey() # NUMS point
    A.set(x.to_bytes(32,'big'))
    r = random.randrange(1, SECP256K1_ORDER)
    p = SECP256K1.mul([(SECP256K1_G, r)]) # rG
    ret = ECPubKey() # A + rG
    ret.p = p
    ret.valid = True
    ret.compressed = True
    final = ECPubKey()
    final = ret + A
    print(f"NUMS point: {final}")

    # Creating 2 tapleafs:
    tapscripts = list()
    # 1: 2-of-2 PKs
    tapscript_multisig = TapLeaf().construct_csa(2, [Y, PK_R])
    # tapscript_multisig = TapLeaf().construct_pk(Y)
    tapscripts.append(tapscript_multisig)
    # 2: PK_A + TimeLock
    tapscript_delay = TapLeaf().construct_pk_delay(Y, 10)
    tapscripts.append(tapscript_delay)
    for tapscript in tapscripts:
        for op in tapscript.script:
            print(op.hex()) if isinstance(op, bytes) else print(op)
        print()

    # P2TR Locking
    tapscript_weights = [(1, tapscript) for tapscript in tapscripts]
    multisig_taproot = TapTree(key = final)
    multisig_taproot.huffman_constructor(tapscript_weights)
    # Derive segwit v1 address
    tapscript, taptweak, control_map = multisig_taproot.construct()
    taptweak = int.from_bytes(taptweak, 'big')
    output_pubkey = final.tweak_add(taptweak)
    output_pubkey_b = output_pubkey.get_bytes()
    segwit_address = program_to_witness(1, output_pubkey_b)
    print(f"P2TR Address: {segwit_address}")

    return segwit_address, tapscript, taptweak, control_map, tapscript_multisig

def verify_adaptor_signature(R_adap, T, Y, sighash, adaptor_signature):
    # Adaptor Signature Verification
    R_T = SECP256K1.affine(SECP256K1.add(R_adap, T))
    print(f"R_T: {R_T}")
    e_adap = int.from_bytes(TaggedHash("BIP0340/challenge", R_T[0].to_bytes(32, 'big') + Y.get_bytes() + sighash), 'big') % SECP256K1_ORDER
    R_1 = SECP256K1.add(SECP256K1.mul([(SECP256K1_G, int.from_bytes(adaptor_signature, 'big'))]), T)
    R_2 = SECP256K1.negate(SECP256K1.mul([(Y.p, e_adap)]))
    R_verfier = SECP256K1.affine(SECP256K1.add(R_1, R_2))
    return R_T == R_verfier

# Helper function for Twisted ElGamal encryption
def twist_elgamal_encrypt(r, message, pubkey, H):
    v = SECP256K1.affine(SECP256K1.mul([(pubkey, r)]))
    u = SECP256K1.affine(SECP256K1.add(
        SECP256K1.mul([(SECP256K1_G, message)]),
        SECP256K1.mul([(H, r)])
    ))
    return (u, v)

# Divide Adaptor value into 8 parts of 32bits each
def divide_256bit_to_32bit_parts(number_256bit: int):
    if number_256bit.bit_length() > 256:
        raise ValueError("Number exceeds 256 bits")

    parts = []
    for i in reversed(range(8)):
        part = (number_256bit >> (i * 32)) & 0xFFFFFFFF
        parts.append(part)
    return parts

# recombine 32-bit parts back into the original 256-bit number
def combine_32bit_parts_to_256bit(parts: list[int]) -> int:
    if len(parts) != 8:
        raise ValueError("Exactly 8 parts required")
    number_256bit = 0
    for i, part in enumerate(reversed(parts)):
        if part.bit_length() > 32:
            raise ValueError(f"Part {i} exceeds 32 bits")
        number_256bit |= (part << (i * 32))
    return number_256bit

# Prove correct twisted Elgamal encryption
def prove_correct_twisted_elgamal_encryption(H, PK_A, t, U, beta):
    s1 = random.randrange(1, SECP256K1_ORDER)
    s2 = random.randrange(1, SECP256K1_ORDER)
    A1 = SECP256K1.affine(SECP256K1.mul([(SECP256K1_G, s1)]))
    A2 = SECP256K1.affine(SECP256K1.mul([(H, s2)]))
    A3 = SECP256K1.affine(SECP256K1.mul([(PK_A, s2)]))
    e = int.from_bytes(TaggedHash("BIP0340/challenge", 
                                        A1[0].to_bytes(32, 'big') + 
                                        A2[1].to_bytes(32, 'big') + 
                                        A3[0].to_bytes(32, 'big') + 
                                        U[0].to_bytes(32, 'big')), 'big')
    z1 = (s1 + e * t.as_int()) % SECP256K1_ORDER
    z2 = (s2 + e * beta) % SECP256K1_ORDER
    return e, z1, z2

# Verify correct twisted Elgamal encryption
def verify_correct_twisted_elgamal_encryption(T, H, PK_A, U, V, e, z1, z2):
    neg_e_T = SECP256K1.negate(SECP256K1.mul([(T, e)]))
    A1_chk = SECP256K1.affine(SECP256K1.add(SECP256K1.mul([(SECP256K1_G, z1)]), neg_e_T))

    subT = SECP256K1.negate(T)
    UsubT = SECP256K1.affine(SECP256K1.add(U, subT))
    neg_e_UsubT = SECP256K1.negate(SECP256K1.mul([(UsubT, e)]))
    A2_chk = SECP256K1.affine(SECP256K1.add(SECP256K1.mul([(H, z2)]), neg_e_UsubT))

    neg_e_V = SECP256K1.negate(SECP256K1.mul([(V, e)]))
    A3_chk = SECP256K1.affine(SECP256K1.add(SECP256K1.mul([(PK_A, z2)]), neg_e_V))
    e_chk = int.from_bytes(TaggedHash("BIP0340/challenge", 
                                        A1_chk[0].to_bytes(32, 'big') + 
                                        A2_chk[1].to_bytes(32, 'big') + 
                                        A3_chk[0].to_bytes(32, 'big') + 
                                        U[0].to_bytes(32, 'big')), 'big')
    return e == e_chk

# Twisted Elgamal Decryption
def twisted_elgamal_decrypt(enc_adaptor_list, sk_A):
    M_list = [0]*8
    for i, (u_i, v_i) in enumerate(enc_adaptor_list):
        _neg_dk_v = SECP256K1.negate(SECP256K1.mul([(v_i, sk_A)]))
        M_i = SECP256K1.affine(SECP256K1.add(u_i, _neg_dk_v))
        M_list[i] = M_i

    return M_list

# === Cache-aware Shank's algorithm ===
def run_shanks_algorithm(M_list):
    _baby_step_cache = {}
    # === Recover 32-bit scalars from M_list ===
    start = time.process_time()
    recovered_segments = []
    for i, pt in enumerate(M_list):
        scalar = shanks_discrete_log_cached(_baby_step_cache, pt, SECP256K1_G, max_exponent=2**32)
        recovered_segments.append(scalar)
        print(f"Segment {i}: scalar = {scalar}")

    # Optionally recombine to 256-bit number
    recovered_number = 0
    for i, seg in enumerate(recovered_segments):
        recovered_number |= seg << (32 * (7 - i))

    end = time.process_time()
    print(f"Execution time: {end - start:.4f} seconds")
    return recovered_number

# Build baby-step table for Shank's algorithm: 2^(bits/2 + tunning) entries
def build_baby_steps(G, m):
    baby_steps = {}
    for i in range(m):
        pt = SECP256K1.affine(SECP256K1.mul([(G, i)]))
        baby_steps[pt] = i
    return baby_steps

# Shank's algorithm with cached baby-step table
def shanks_discrete_log_cached(_baby_step_cache, Q, G=SECP256K1_G, max_exponent=2**32):
    m = math.isqrt(max_exponent) + 1
    key = G

    if key not in _baby_step_cache:
        _baby_step_cache[key] = build_baby_steps(G, m)
        cache_size_bytes = asizeof.asizeof(_baby_step_cache)
        cache_size_mb = cache_size_bytes / (1024 * 1024)
        print(f"Total cache size: {cache_size_mb:.2f} MB")

    baby_steps = _baby_step_cache[key]
    mG = SECP256K1.mul([(G, m)])
    mG_neg = SECP256K1.negate(mG)

    for j in range(m):
        guess = SECP256K1.affine(SECP256K1.add(Q, SECP256K1.mul([(mG_neg, j)])))
        if guess in baby_steps:
            i = baby_steps[guess]
            return j * m + i
    raise ValueError("Discrete log not found")

# Build baby-step table for Shank's algorithm: 2^(bits/2 + tunning) entries
def build_baby_step_lookup(G, bits=32, tunning=0):
    """
    Build baby-step table for Shank's algorithm: 2^(bits/2 + tunning) entries
    """
    m = 2**(bits // 2 + tunning)
    print(f"Building baby-step table with {m} entries...")

    lookup = {}
    for i in tqdm(range(m), desc="Computing baby steps"):
        pt = SECP256K1.affine(SECP256K1.mul([(G, i)]))
        lookup[pt] = i
    return lookup

# Save baby-step lookup to disk
def save_lookup_to_disk(lookup, path):
    with open(path, "wb") as f:
        pickle.dump(lookup, f)
    print(f"Saved baby-step lookup to {path}")

# Load baby-step lookup from disk
def load_lookup_from_disk(path):
    with open(path, "rb") as f:
        return pickle.load(f)

# Recover discrete log using cached baby-step table
def recover_discrete_log(Q, G, lookup, bits=32, tunning=0):
    """
    Recovers x such that Q = x*G using precomputed baby-step hash table (lookup).
    """
    m = 2**(bits // 2 + tunning)  # baby-step size
    n = 2**(bits // 2 - tunning)  # number of giant steps

    mG = SECP256K1.mul([(G, m)])
    mG_neg = SECP256K1.negate(mG)

    for j in range(n):
        test_point = SECP256K1.affine(SECP256K1.add(Q, SECP256K1.mul([(mG_neg, j)])))
        if test_point in lookup:
            i = lookup[test_point]
            return j * m + i

    raise ValueError("Discrete log not found in cached range")