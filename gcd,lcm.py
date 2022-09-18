def gcd(a, b):
  assert a >= 0 and b >= 0 and a + b > 0
  while a > 0 and b > 0:
    if a >= b:
      a = a % b
    else:
      b = b % a
  return max(a, b)


def lcm(a, b):
    assert a > 0 and b > 0
    i=gcd(a,b)
    return (a*b)/i

def extended_gcd(a, b):
    assert a >= b and b >= 0 and a + b > 0
    if b == 0:
        d, x, y = a, 1, 0
    else:
        (d, p, q) = extended_gcd(b, a % b)
        x = q
        y = p - q * (a // b)

    assert a % d == 0 and b % d == 0
    assert d == a * x + b * y
    return (d, x, y)

def ExtendedEuclid(a,b):
    assert a >= b and b >= 0 and a + b > 0
    if b == 0:
        d, x, y = a, 1, 0
    else:
        (d, p, q) = extended_gcd(b, a % b)
        x = q
        y = p - q * (a // b)

    assert a % d == 0 and b % d == 0
    assert d == a * x + b * y
    return (x, y)

def diophantine(a, b, c):
    assert c % gcd(a, b) == 0
    if a>b:
        (d,x,y)=extended_gcd(a,b)
    else:
        (d,y,x)=extended_gcd(b,a)
    i=c//d
    return (x*i, y*i)

def squares(n, m):
    i=gcd(n,m)
    return (n * m)/(i*i)

def divide(a, b, n):
    assert n > 1 and a > 0 and gcd(a, n) == 1
    if a>n:
        (d,x,y)=extended_gcd(a,n)
    else:
        (d,y,x)=extended_gcd(n,a)
    num=x*b
    while num<0:
        num+=n
    return num

def ChineseRemainderTheorem(n1, r1, n2, r2):
    (x, y) = ExtendedEuclid(n1, n2)
    num=r2*x*n1 + r1*y*n2
    ab=n1*n2
    while abs(num)>ab:
        num=num%ab
    if num<0:
        num+=ab
    return num

#def FastModularExponentiation(b, k, m):
#    previous=b%m
#    while k!=0:
#        previous=previous*previous
#        previous=previous%m
#        k-=1
#    return previous

def extend(b,iteration,m,counter,ans_prev):
    if 2*counter<=iteration:
        ans=(ans_prev*ans_prev)%m
        new_counter=2*counter
        (iteration,ans)=extend(b,iteration,m,new_counter,ans)
        if iteration>=counter:
            ans=(ans_prev*ans)%m
            iteration-=counter
            return (iteration,ans)
        else:
            return (iteration,ans)
    else:
        iteration-=counter
        return(iteration,ans_prev)

def FastModularExponentiation(b, e, m):
    counter=1
    ans=b%m
    (iteration,ans)=extend(b,e,m,counter,ans)
    return ans


def totient_function(num):
    count=0
    for x in range(num):
        if x<=1:
            continue
        if gcd(x,num)==1:
            count+=1
    return count+1

def Encrypt(message, modulo, exponent):
    return PowMod(ConvertToInt(message), exponent, modulo)

def Decrypt(ciphertext, p, q, exponent):
    exponent=InvertModulo(exponent,(p-1)*(q-1))
    return ConvertToStr(PowMod(ciphertext, exponent, p * q))
  
def DecipherSimple(ciphertext, modulo, exponent, potential_messages):
    for x in range(len(potential_messages)):
        if ciphertext == Encrypt(potential_messages[x], modulo, exponent):
            return potential_messages[x]
    return "don't know"

def DecipherSmallPrime(ciphertext, modulo, exponent):
    n=2
    while n*n<modulo:
        if modulo % n == 0:
            small_prime = n
            big_prime = modulo // n
            return Decrypt(ciphertext, small_prime, big_prime, exponent)
        n+=1
    return "don't know"

def DecipherSmallDiff(ciphertext, modulo, exponent):
    n=IntSqrt(modulo)
    while not n<=0:
        if modulo%n==0:
            small_prime = n
            big_prime = modulo // small_prime
            return Decrypt(ciphertext, small_prime, big_prime, exponent)
        n-=1
    return "don't know"


def DecipherCommonDivisor(first_ciphertext, first_modulo, first_exponent, second_ciphertext, second_modulo, second_exponent):
    if first_modulo>second_modulo:
        common_prime=GCD(first_modulo,second_modulo)
    else:
        common_prime=GCD(second_modulo,first_modulo)
    if first_modulo % common_prime == 0 and second_modulo % common_prime == 0 and common_prime!=1:
        q1 = first_modulo // common_prime
        q2 = second_modulo // common_prime
        return (Decrypt(first_ciphertext, common_prime, q1, first_exponent), Decrypt(second_ciphertext, common_prime, q2, second_exponent))
    return ("unknown message 1", "unknown message 2")

def DecipherHastad(first_ciphertext, first_modulo, second_ciphertext, second_modulo):
  r = ChineseRemainderTheorem(first_modulo, first_ciphertext, second_modulo, second_ciphertext)
  return ConvertToStr(IntSqrt(r))
  