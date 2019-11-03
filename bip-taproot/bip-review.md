# Taproot review

script validation:

 - q = hash in (output_key)
 - annex_a
 - if len(stack) >= 2 && stack[len(stack)-1][0] == 0x50
      annex_a = stack.pop()
 - if len(stack) == 1
     key spending path
     checker.checksigSchnorr()
 - if len(stack) >= 2
     script = stack[len(stack)-2]
     controlBlock = stack[len(stack)-1]
     ensure len(controlBlock) == 33+32m, mE[0,128]
           !!!! where does the BIP validate the length of controlBlock?
           // len(controlBlock) > 33 && (len(controlBlock) - 33) % 32 == 0
           // m = len(controlBlock)-33/32
     leafVersion = controlBlock[0] & 0xfe
     p = Point(controlBlock[1:33]) - fail if not on curve
     k0 = taggedSha256("TapLeaf", leafVersion || compact_size(len(script)) || script)
     for j := 0; j < m-1; j++ 
       ej = c[33+32j:65+32j]
       if lexicographic_cmp(kj, ej) >= 0
         kj+1 = taggedSha256("TapBranch", ej||kj)
       else
         kj+1 = taggedSha256("TapBranch", kj||ej)
     t = taggedSha256("TapTweak", p || km)
     if t >= curve.N
       return 0
     if controlBlock[0]&1 == 1
       Q = point(q)
     else
       Q = -point(q)
     if Q != P+int(t)
       return 0
     
transaction digest

 - question - scriptpubkey is committed, but not the actual branch
   why scriptPubKey and not the scriptCode

 - interesting that it commits to anything determined by state of witness
   normally don't put things in the scriptSig or witness for other signature
   schemes.
