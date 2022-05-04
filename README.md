# RUSHB - A basic protocol simulation

<img src="https://storage.googleapis.com/starfighter-public-bucket/wiki_images/resume_photos/RUSHB/00001.jpg"
    width="700px">

When applying for jobs, one of the first impressions you want to give is
"Yes, I can read a specification, and implement said spec, according to (some) 
style guide".

## Aims

This repo contains the implementation for a computer networking assignment I 
did in University. The purpose of said assignment was:

1. Get familiar with how to read RFC documents.
2. Get familiar with how to implement the functionality of an RFC (practicality
    wasn't the aim, hence we were free to implement such a protocol in `Python`).
3. If we hadn't realised in CSSE2310 (when Joel was teaching it that is),
    understand and embrace the idea of **your code MUST work** (no points for
    effort, only functionality).

## How do I use this thing?
To see how the software works, do the following:

1. Clone the repo and, with your favourite terminal, `cd` into the 
        `RUSHBProtocol` directory (you should be able to see the `RUSHBSvr.py`
        file using the appropriate directory list command). 
2. In this terminal, run the following command:
```
python3 RUSHBSvr.py
```
Which (if `__DEBUG_ENABLED__` is set to `False`) should print a 5 digit number
    to `stdout`.

```
# e.g.
>>> python3 RUSHBSvr.py
12345
```
3. Remember this number, now in another terminal, `cd` into the same directory
    and run this command:

```
python3 RUSHBSampleClient.py 11111 12345 -v 3 -m SIMPLE
```

- The first parameter, `11111`, is the **client port number**. It is used to 
    uniquly identify this client on our local network (kind of like how `NAT` 
    works).

- The second parameter, `12345` is the **server port number**. It is used by the
    client to send packets to the server (since this is only meant to run on
    a local network).

- The third (optional) parameter, `-v`, specified whether the client wants
    **verbose** output.

- The fourth (optional) parameter, `-m` specifies the mode the client will
    run under. There are a number of modes, and they're covered below.

- The fifth and final (optional) parameter, `-o` specifies the output filename
    from the client (i.e. store the verbose output in a file for later 
    comparison).

In general usage is as follows:

```
python3 RUSHBSampleClient.py client_port server_port [-v verbose][-m mode][-o output]
```

### What modes can I use
The available modes, `[-m mode]`, are as follows:
- `SIMPLE` = [Send GET, ... work normally until the rest of the packets]
- `NAK` = [Send GET, Send NAK, ... work normally until the rest of the packets]
- `MULTI_NAK` = [Send GET, Send NAK, Send NAK, Send NAK, ... 
        work normally until the rest of the packets]
- `TIMEOUT` =  [Send GET, Drop the DAT received, ... work normally until the 
        rest of the packets]
- `MULTI_TIMEOUT` = [Send GET, Drop the DAT received, Send NAK, Drop the DAT 
        received, ... work normally until the rest of the packets]
- `INVALID_SEQ` = [Send GET, Send packet with an invalid seq#, ... work 
        normally until the rest of the packets]
- `INVALID_ACK` = [Send GET, Send packet with an invalid ack#, ... work 
        normally until the rest of the packets]
- `INVALID_FLAGS` =  [Send GET, Send packet with an invalid flag#, ... work 
        normally until the rest of the packets]
- `CHECKSUM` = [Send GET with CHK, ... work normally until the rest of the 
        packets]
- `INVALID_CHECKSUM_VAL` = [Send GET with CHK but use faulty checksum value, 
        ... work normally until the rest of the packets]
- `INVALID_CHECKSUM_FLAG` = [Send GET with CHK, Send packet with CHK not set, 
        ... work normally until the rest of the packets]

### How do I know if your output is correct?
We were provided with the files seen in the `expected_output` folder as a means
    to verify our implementations' output.

## How long did this take to write?
The following files were written and tested in about ~1 week (5 working days).

- `RUSHBSvr.py`
- `RUSHBMultiprocessing.py`
- `RUSHBPacket.py`
- `RUSHBHelpers.py`

All other files were provided by the course for this specific assignment.