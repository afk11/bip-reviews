
nonce_function_bipschnorr
 - fail if counter != 0 (nonce reuse issue)
 - if algo16 non-null:
      if algo16 == "BIPSchnorrDerive": init sha with tagged bipschnorr midstate
      else: init sha tagged with algo16
 - else: initialize sha tagged with "BIPSchnorrNull"
 - update sha with key32
 - update sha with msg32
 - if data != NUILL, update sha with data

static int secp256k1_ec_pubkey_absolute
 - load pubkey to ge
 - sets sign to zero by default
 - negates point if ge.Y !is_quad_var, and sets sign=1
 - writes resulting ge to pubkey

secp256k1_xonly_pubkey_create
 - calls secp256k1_ec_pubkey_create. return 0 if fails.
 - convert to absolute with secp256k1_ec_pubkey_absolute
 - return successful
 * ensures xonly_pubkey is absolute

secp256k1_xonly_pubkey_parse
 - copies into 33 byte buffer with prefix 0x02
 - calls secp256k1_ec_pubkey_parse
 - convert to absolute with secp256k1_ec_pubkey_absolute
 * ensures xonly_pubkey is absolute

note: 
 - prefixes indicate whether ge.Y was even, not
   if it's negative/positive

secp256k1_xonly_pubkey_serialize
 - cast to secp256k1_pubkey and call secp256k1_ec_pubkey_serialize
 - writes bytes 1->33 to output32

secp256k1_xonly_pubkey_from_pubkey
 - pubkey is cast to secp256k1_xonly_pubkey and written to xonly_pubkey
 - calls secp256k1_ec_pubkey_absolute on xonly_pubkey (using cast to secp256k1_pubkey), sign is updated
 * ensures xonly_pubkey is absolute

secp256k1_xonly_pubkey_to_pubkey
 - xonly_pubkey is cast to secp256k1_pubkey, written to pubkey
 - if (sign), original was !is_quad_var, and would have been modified
   convert back with secp256k1_ec_pubkey_negate
 * preserves original sign

secp256k1_xonly_privkey_tweak_add
 - convert seckey to pubkey to check is_quad_var. 
 - if !is_quad_var, privkey needs to be negated.
 - if negation fails, return 0
 - perform secp256k1_ec_privkey_tweak_add

secp256k1_xonly_pubkey_tweak_add
 - internal_pubkey is cast to secp256k1_pubkey, and written to *output_pubkey
 - performs secp256k1_ec_pubkey_tweak_add

secp256k1_xonly_pubkey_tweak_verify
 - secp256k1_xonly_pubkey_tweak_add on internal pubkey, writing to pk_expected. 
   returns 0 if fails
 - tests that memory from output_pubkey == pk_expected we generated


schnorrsig/main_impl.h

secp256k1_schnorrsig_serialize
 - copies 64byte sig->data to out64
 - returns 1 always

secp256k1_schnorrsig_parse
 - copies in64 to sig->data
 - returns 1 always

secp256k1_schnorrsig_sign
 - noncefp defaults to secp256k1_nonce_function_bipschnorr if null
 - scalar_set_b32, x, seckey. if overflow, return 0
 - convert priv to public (pkj)
 - convert secp256k1_gej pkg to secp256k1_ge pk
 - if !is_quad_var(pk.y), negate private key
 - if nonce function fails (algo16:BIPSchnorrDerive, counter:0)
      wipe sig, wipe scalar x, return 0
 - init scalar k for nonce
 - if scalar zero, wipe sig, wipe scalar x, return 0
 - ecmult(&rj, k)
 - convert rj to r (secp256k1_ge_set_gej)
 - if r.y !is_quad_var, negate scalar k
 - normalize r.x, write r.x from s->data[0]
 - initialize BIPSchnorr tagged hash
 - update hash with r.x
 - update hash with pubkey.x
 - update hash with nonce
 - update hash with msg32
 - finalize hash to buf
 - load buf to scalar e
 - e = (e*x)%n
 - e = (e+k)%n (? ? is this modulo? what does secp256k1_scalar_mul and add do?)
 - copy e from sig->data[32]
 - clear k, clear x (sensitive)
 - return 1
 * performs key prefixing
 * line by line comparison to bip checks out

secp256k1_schnorrsig_real_verify
 - negate e (hashed message)
 - load public key from xonly_pubkey
 - convert pkp to pkj (jacobian)
 - perform scalar mult, scalar mult, write to rj

secp256k1_schnorrsig_verify
 - if rx (secp256k1_fe) can't be initialized from sig[0], return 0
 - set s (secp256k1_scalar) from sig[32]. 
 - if s overflowed, return 0
 - init sha as secp256k1_schnorrsig_sha256_tagged
 - update hash with r.x
 - update hash with pubkey
 - update hash with msg32
 - finalize hash to buf
 - call secp256k1_schnorrsig_real_verify which produces rj. if fails, return 0
 - check rj.y is_quad_var, if not, return 0
 - check rj.x == rx, if not, return 0
 - signature valid
 * key prefixing

question: why does secp256k1_schnorrsig_parse copy
and not validate rx and s?


secp256k1_schnorrsig_verify_batch_init_randomizer(ctx, sha, []sig, []msg32, []pk, nsigs)
  if n_sigs > 0, arrays must not point to NULL (ARG_CHECK)
  for i := 0; i < nsigs; i++:
    sha256_write(sha, sig[i][0:64])
    sha256_write(sha, msg32[i])
    sha256_write(sha, pk[i]) <-- COMPRESSED serialization
  build ecmult_context. wraps ctx, []sig, []msg32, nsigs 
* doc: initialize sha with state, serializing each sig, msg32, pk serially.

// (a0(==1)*s0)+(a1*s1)..+(an*sn)
secp256k1_schnorrsig_verify_batch_sum_s(s, chacha_seed, []sig, nsigs)
  randomizer_cache[2] <-- recompute as we go? matches later on?
  for i = 0; i < nsigs; i++ {
    secp256k1_scalar term
    if i%2==1 // .., 1, .., 3, .., 5, etc
      secp256k1_scalar_chacha20() write to randomizer_cache[0]
    load sig.s into term
    return 0 if overflows
    term = term(==s)*randomizer_cache[i%2] // 0, 1, 0, 1, 0, 1
    s = s+term
  }
  return 1
* doc: sums each sig.s into s

secp256k1_schnorrsig_verify_batch_ecmult_callback(secp256k1_scalar* sc, secp256k1_ge *pt, idx, void* data)
 - data pointer interpreted as secp256k1_schnorrsig_verify_ecmult_context
 - called called nsigs*2 times. for s, and for R
 - if idx%2==0 // 0, 1, 0, 1, 0, 1 - R case
     secp256k1_fe rx.
     write randomizer to *sc
     if set_b32 to rx fails with sig.r
       return 0
     if rx !is_quad_var
       return 0
 - else // eP
     buf[32]
     secp256k1_sha256 sha
     initialize sha with secp256k1_schnorrsig_Sha256_Tagged
     update sha with r||pk||msg, finalize into buf
     write buf to *sc
     sc = sc*randomizer_cache element
     if we cannot load the public key
       return 0
 * follows key prefixing
     

secp256k1_schnorrsig_verify_batch(ctx, scratch, []sigs, []msg32, []pk, nsigs)
  secp256k1_schnorrsig_verify_ecmult_context ecmult_context
  secp256k1_sha256 sha
  secp256k1_scalar s (combined signature s values?)
  secp256k1_gej rj (jacobian point, combined r?)
  init sha using secp256k1_sha256_initialize
  if !secp256k1_schnorrsig_verify_batch_init_randomizer(ctx, sha, sig, msg32, pk, nsigs)
    return 0
  sha further initialized with each (sig, msg32, pk) 
  sha finalized, into ecmult_context.chacha_seed
  ecmult_context.randomizer_cache[0] set to `1`
  clear scalar value s.
  if !secp256k1_schnorrsig_verify_batch_sum_s(s, ecmult_context.chacha_seed, sig, nsigs)
    return 0
  negate s // s=-(s1+a2*s2..an*sn)
  if !secp256k1_ecmult_multi_var(scratch, &rj, &s, callback, void* data, 2*nsigs) // internally uses secp256k1_schnorrsig_verify_batch_ecmult_callback
    return 0
  if !secp256k1_gej_is_infinity(rj)
    return 0
  return 1
