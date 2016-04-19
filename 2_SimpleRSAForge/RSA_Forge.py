# The object of this exercise is to forge a signature on the message:
# "Crypto is hard --- even schemes that look complex can be broken"
# Signatures can be requested for any message except the target message.
#
# The signature is computed using an RSA based scheme, where:
# 1. The message is first prepended to 63 bytes (if req.) and then
#    M is formed as 0x00 m 0x00 m.
# 2. The signature is computed as M^d mod N. (N, e) is the public key
#    and (N,d) is the private key.
#
# In order to crack this, we don't want to solve the discrete logarithm to try to find d.
# Instead, examining the scheme shows that the formation of M will always give:
# M = m*2^512 + m, given that 64 bytes (512 bits) are effectively appended to m, and then m is added onto these appended bytes.
# This gives M = m*(2^512 + 1).
#
# So, the signature is effectively sig = (m*(2^512 + 1))^d mod N
# We cant directly request a signature on m, but we can request signatures for factors of m, say msg1 and msg2 to achieve sig1 and sig2,
# sig1 = (m1*(2^512 + 1))^d mod N
# sig2 = (m2*(2^512 + 1))^d mod N
# We know that sig1 * sig2 will give:
# sig1*sig2 = m1^2*m2^2*(2^512 + 1)^2d mod N
# Really, the signature shoudl be (m1*m2*(2^512+1))^d mod N, so we need to get (2^512 + 1)^-d to multiply through.
# Since the signature for given m is (m*(2^512 + 1))^d mod N, using m = 1 gives (2^512 + 1)^d mod N.
# We can take the modular inverse to get (2^512 + 1)^-d mod N.
# So, the solution is sig1*sig2*modinv(sig(1), N) mod N

from oracle import *
from helper import *

# Decimal value of key.
n = 119077393994976313358209514872004186781083638474007212865571534799455802984783764695504518716476645854434703350542987348935664430222174597252144205891641172082602942313168180100366024600206994820541840725743590501646516068078269875871068596540116450747659687492528762004294694507524718065820838211568885027869

e = 65537 # 10001 hex in decimal.

Oracle_Connect()

# Message to be forged. Note: cannot compute a signature for this message.
msg = "Crypto is hard --- even schemes that look complex can be broken"

m = ascii_to_int(msg)



# Find a factor of the message. Note that the loop range is relatively small.
factor = 0
for i in range(2,100):
    if m % i == 0:
        factor = i
        break

# Define messaged as the factor and message divided by factor.
msg1 = factor
msg2 = m/factor

# Get a signature for each message.
signMsg1 = Sign(msg1)
signMsg2 = Sign(msg2)

# Sign the message '1', so that (2^512 + 1)^d is calculated. 
sign1 = Sign(1)

# Now form a signature using the product of the two signatures for the messages whose product forms the message, and multiply out by inverse of the 
# message for "1" to remove to remove additional (2^512 + 1)^d.
signedMsgFinal = (signMsg1*signMsg2*modinv(sign1, n)) % n

# Check if successfully forged.
Result = Verify(m, signedMsgFinal)
if Result:
    print "Message forged successfully!"
else:
    print "Message not forged successully."

Oracle_Disconnect()
