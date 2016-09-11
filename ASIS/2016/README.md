# SRPP

This is an SRP protocol, which can be described as follows

```
public parameters: N, g, k
secret parameter: x

Client                                                 	   A  	   	    Server
A ↜ R                                                   ------>
x ← hash(salt,email,password)                                           x ← hash(salt,email,password)
                                                       	   b  	   	    b ↜ R
                              	   	   	   	            <------         B ← k × gˣ + gᵇ (mod N)
u ← hash(A,B)                                          	   	   	   	    u ← hash(A,B)
                                                       	   	   	   	   	S ← (A × (gˣ)ᵘ)ᵇ (mod N)
                                                       	   	   	   	   	K ← hash(S)
M ← H(H(N) ⊕ H(g), H(email), salt, A, B, K_client)	   	   	   	   	    M ← H(H(N) ⊕ H(g), H(email), salt, A, B, K_client)
                                                       	  K',M'
                                                       	------->        Server verifies that K = K' and M = M' otherwise rejects
```


We cannot send 0 or N, but obviously sending A = 2N would always cause S to be 0 and then we know K for any secret values. So, we know K and we can easily compute M. This challenge is actually a much simpler version of [this one](https://grocid.net/2016/04/17/plaidctf-tonnerre/).

Running the code gives:

```
ASIS{7bdb4b540699ef341f4a3b32469cd3f6}
```