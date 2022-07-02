import glob, subprocess, random, time, threading, os, hashlib


# Return code for Segmentation Fault
SIGSEGV = -11

# Run one fuzz case with the provided input (which is a byte array)
def fuzz(thread_id: int, in_bytes: bytearray):
    assert isinstance(thread_id, int)
    assert isinstance(in_bytes, bytearray)

    tmpfn = f"tmpinput{thread_id}"

    # Write out the input to a temporary file
    with open(tmpfn, "wb") as fd:
        fd.write(in_bytes)

    # Run objdump with the provided input
    # Make sure to pipe the output so we dont bottleneck on printing
    sp = subprocess.Popen(["./objdump", "-x", tmpfn],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
    ret_code = sp.wait()

    # Assert that the program ran successfully
    if ret_code != 0:
        print(f"Exited with {ret_code}")

        if ret_code == SIGSEGV:
            crash_sha256 = hashlib.sha256(in_bytes).hexdigest()
            # If we are segfaulting, save the file
            open(os.path.join("crashes", f"crash_{crash_sha256}"),
                    "wb").write(in_bytes)


# Get a listing of all the files in the corpus
# The corpus is the set of files which we pre-seeded the fuzzer with to give it valid inputs.
# These are files that the program should be able to handle parsing, that we will ultimately mutate
# and splice together to try to find bugs!
corpus_filenames = glob.glob("corpus/*")

# Load the corpus files into memory
corpus = set()

# Dedup files which are not unique. Ignore symbolic links
for filename in corpus_filenames:
    corpus.add(open(filename, "rb").read())

# Convert the corpus back into a list
corpus = list(map(bytearray, corpus))

# Get the time at the start of the fuzzer
start = time.time()

# Total number of fuzz cases
cases = 0

def worker(thread_id):
    global start, corpus, cases

    while True:
        # Create a copy of an existing input from the corpus
        bytes_in = bytearray(random.choice(corpus))

        # Mutator for our fuzzer
        for _ in range(random.randint(1, 8)):
            bytes_in[random.randint(0, len(bytes_in)-1)] = random.randint(0, 255)

        # Pick a random input from our corpus
        fuzz(thread_id, bytes_in)

        # Update number of fuzz cases
        cases += 1

        # Determine the amount of second we have been fuzzing for
        elapsed = time.time() - start

        # Determin the number of fuzz cases per second
        fcps = float(cases) / elapsed

        if thread_id == 0:
            print(f"[{elapsed:10.4f}] cases {cases:10} complete! | {fcps:10.4f} ")


NUM_THREADS = 10
# Spawn `NUM_THREADS`
for thread_id in range(NUM_THREADS):
    threading.Thread(target=worker, args=[thread_id]).start()

# Wait for all the threads to complete
while threading.active_count() > 1:
    time.sleep(0.1)
