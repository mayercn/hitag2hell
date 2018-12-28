from maskgen import *
from hitag2 import *

## Christian Mayer:
## The main idea of the guess-and-determine algorithm is the following:
## Assume we know the keystream (because we are the attacker and have access to the sender).
## Now, we try to "guess" the internall state of the LFSR that has generated this keystream.
## It's basically like an inverse 2-level filter function (that's why the inverse f() function is
## defined in hitag2.py). We guess the internal state bit by bit (from the keystream). Because 20 bits
## of the LFSR are responsible for a single keystream bit, there are MANY internal states of the LFSR that would have
## generated this keystream bit. But we know the keystream bit result, so basically half of the internal states of
## the LFSR cannot have produced this result (they would produce the bit: 1-result). This "halving" of the search
## space is the main idea of the guess-and-determine algorithm.

def popcount(x):
    return "{0:0b}".format(x).count('1')

masks, last_lfsr_guess = generate_masks()
bits = [popcount(x) for x in masks]

state = hitag2_init(0x414141414141, 0x42424242, 0x43434343)
keystream_int = hitag2(state,32)
keystream = map(int, "{0:032b}".format(keystream_int))
#print keystream
def expand(mask, x):
    res = 0
    for i in range(0, 48):
        if mask & 1:
            res |= (x & 1)<<i
            x >>= 1
        mask >>= 1
    return res

def compress(mask, x):
    result = 0;
    bits_eaten = 0;
    bit_index = 0
    while bits_eaten < popcount(mask):
        if((mask>>bit_index)&1):
            if((x>>bit_index)&1):
                result |= (1 << bits_eaten)
            bits_eaten += 1
        bit_index += 1
    return result

def test(state):
    for bit in range(len(masks), 32):
        if f20(state) != keystream[bit]:
            return
        state = lfsr(state)
    for _ in range(32):
        state = lfsr_inv(state)
    print hex(state)

#test(state)

test_states = []
for _ in range(len(masks)):
    test_states.append(state)
    state = lfsr(state)


def fill_layer(state, layer, filt_mask=0x5806b4a2d16c):
    
    ## Christian Mayer:
    ## Suppose, you have guessed the 20 LFSR bits, given a single keystream bit.
    ## These are the exact positions: 2,3,5,6,8,12,14,15,17,21,23,26,28,29,31,33,34,43,44,46.
    ## Have a look at Figure 11 of https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final95.pdf
    ## Now, you read the next keystream bit. The LFSR has shifted by one bit now. But the guesses from the previous
    ## keystream bit are still valid. So many of the bits are already guessed, you only need to guess the bits that
    ## are not yet guessed. This is exactly what a layer is for. The layer is a series of zeros and ones that you have already
    ## guessed (and some holes that you need to guess in subsequent layers). As each layer uses the guesses from previous
    ## layers, the function is recursive (using the lower layers for the higher layers). The variable filt_mask simply stores
    ## a "1" if the layer has a hole (i.e., we have not guessed it, yet). After 9 layers, we have guessed all bits of the
    ## LFSR state. This is one possible solution.
    
    if layer < len(masks):
        for fill in range(0, 1<<bits[layer]):
            new_state = state | expand(masks[layer], fill)
            # debug test
            if testing and (new_state & filt_mask) != (test_states[layer] & filt_mask):
                continue
            #print layer, hex(new_state), fill
            if f20(new_state) != keystream[layer]:
                continue
            if layer < last_lfsr_guess:
                fill_layer(new_state>>1, layer+1, filt_mask)
                fill_layer((new_state>>1) | (1<<47), layer+1, filt_mask)
            else:
                fill_layer(lfsr(new_state), layer+1, filt_mask)
    else:
        test(state)


        
if __name__ == "__main__":
    testing = True
    fill_layer(0, 0)
