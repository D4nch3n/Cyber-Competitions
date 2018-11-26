#NOTE: THIS DID NOT WORK AT THE END :(
def xor(encrypted, key):
  output = ''
  for i in range(len(encrypted)):
    output += chr(ord(encrypted[i]) ^ ord(key[i % len(key)]))
  return output
key_len = 9
possible_key_vals = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
def test(encrypted, key):
  out = xor(encrypted, str(key))
  print(str(key))
  if 'TUCTF' in out:
    return 1
  else:
    return 0
  
def getIndex(l, c):
  for i in range(len(possible_key_vals)):
    if possible_key_vals[i] == c:
      return i
  return -1
def permuteKey(key, startindex):
  rotated = 0
  key_copy = list(key)
  index = startindex
  while rotated == 0:
    i = getIndex(possible_key_vals, key_copy[index])
    if i == (len(possible_key_vals) - 1):
      key_copy[index] = possible_key_vals[0]
      index = index - 1
    else:
      key_copy[index] = possible_key_vals[i + 1]
      rotated = 1
  return str(key_copy)
with open('encrypted', 'r') as f:
  enc = ''.join(f.readlines()).rstrip('/n')
possible_key = "AAAAAAAAA"
solved = 0
while solved == 0:
  val = test(enc, possible_key)
  if val == 1:
    print "DECRYPTION KEY FOUND!"
    print(xor(enc, possible_key))
    print(possible_key)
    solved = 1
  else:
    possible_key = permuteKey(possible_key, len(possible_key) - 1
