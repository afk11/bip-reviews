schnorr:
 - provable security theorem. SUF-CMA (https://blog.cryptographyengineering.com/euf-cma-and-suf-cma/)
   SUF-CMA > EUF-CMA
   non-malleability
 - linear signatures/public keys, brings benefits (multisig)
 - also, batch verification

new signature encoding:
 - fixed 64byte encoding (cf STRICT_DER https://github.com/sipa/bips/blob/bip-schnorr/bip-0066.mediawiki)

new public key encoding (32 byte)

design:

m=message
P=public key
point R, integers e and s picked by signer

e=hash(R||m)
s.G = R+ e.P

two possible formulations, reveal (e,s) or (R, s)

(R, s) formulation supports batch verification

encoding R and public point P
tradeoff between space and verification, prioritize space saving
32byte public key, 64byte signature

Y coordinate of R and P cannot be ambiguous
3. Y coordinate that is a quadratic residue (has a square root mod p)
chosen for R and P. for R, makes signing slower, verification faster (jacobian coordinates)

niggling notion answered by bip
 - no security reduction

## tagged hashes

instead of using native SHA256, use tagged hashes
init hash context with sha256(tag) || sha256(tag) to fill the 64-byte block size of SHA256

signature satisfies: 
m s.G = R + tagged_hash(r || pk || m).P

## applications

 - musig: key aggregation and joint signatures
          n-of-n ms appearing the same as ordinary signatures
          distributed key generation for k-of-n
 - adaptor signatures. (https://download.wpsoftware.net/bitcoin/wizardry/mw-slides/2018-05-18-l2/slides.pdf)
 - blind signatures

# Actions required:
 - worth reviewing patent?
 - review bip-schnorr code - in progress, batch verification left to do
 - find key elements in BIP and review implementation
   (R signature impl, quadratic residue test where necessary,
    public key generation, sign/verify)


