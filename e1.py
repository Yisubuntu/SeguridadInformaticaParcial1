# Ejercicio 1
import Crypto.Util.number as n
import Crypto as c
import hashlib
bits = 1024

# Obtener los primos para Alice y Bob
pA = n.getPrime(bits, randfunc=c.Random.get_random_bytes)
print("pA: ",pA,"\n")
qA = n.getPrime(bits, randfunc=c.Random.get_random_bytes)
print("qA: ",qA,"\n")

pB = n.getPrime(bits, randfunc=c.Random.get_random_bytes)
print("pB: ",pB,"\n")
qB = n.getPrime(bits, randfunc=c.Random.get_random_bytes)
print("qB: ",qB,"\n")

# Obtenemos la primera parte de la llave pública de Alice y Bob
nA = pA * qA
print("nA: ",nA,"\n")

nB = pB * qB
print("nB: ",nB,"\n")

# Calculamos el Indicador de Euler Phi
phiA = (pA-1)*(qA-1)
print("phiA: ",phiA,"\n")

phiB = (pB-1)*(qB-1)
print("phiB: ",phiB,"\n")

e = 65537

# Calcular la llave privada de Alice y Bob
dA = n.inverse(e, phiA)
print("dA: ",dA,"\n")

dB = (n.inverse(e, phiB))
print("dB: ",dB,"\n")

# Ciframos el mensaje
msg = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis pharetra arcu sit amet arcu dictum, ac pretium sem porta. Cras id risus augue. Donec a pellentesque eros, at pretium ipsum. Suspendisse potenti. Praesent vestibulum sodales magna sit amet efficitur. Sed feugiat odio aliquam nisi dapibus, sed ullamcorper sem facilisis. Donec felis justo, malesuada in ante quis, vestibulum hendrerit dolor. Nulla a consectetur lorem. Praesent mattis vel eros ac suscipit. Duis in facilisis magna. Nam id ipsum magna. Integer leo tortor, ultricies ac leo id, laoreet pretium est. Praesent tincidunt sed magna eget commodo. Praesent vitae augue et quam interdum mattis nec vitae enim. Donec quis placerat nisi. Vivamus cursus tellus arcu, a tincidunt odio cursus in. Maecenas sit amet finibus risus. Ut id dolor pretium, luctus mi eu, congue ante. Nunc malesuada metus nec eleifend condimentum. Morbi ornare quam nunc, vel consequat metus congue at. Mauris sit amet sollicitudin tellus. Praesent at erat mi. Phasellus tincidunt, nulla sed congue turpis duis."
print("Mensaje original: ",msg,"\n")
print("Longitud del mensaje en bytes: ",len(msg.encode("utf-8")),"\n")

# Dividimos en partes de 128 caracteres
msg_parts = [msg[i:i+128] for i in range(0, len(msg), 128)]

# Convertir el mensaje a número
m = [int.from_bytes(part.encode("utf-8"), byteorder="big") for part in msg_parts]
print("Mensaje convertido en entero: ",m,"\n")

# Ciframos el mensaje
c = [pow(part, e, nB) for part in m]
print("Mensaje cifrado: ",c,"\n")

# Desciframos el mensaje
des = [pow(part, dB, nB) for part in c]
print("Mensaje descifrado: ",des,"\n")

# Convertimos el mensaje de número a texto
final_parts = [part.to_bytes((part.bit_length() + 7) // 8, byteorder="big").decode("utf-8") for part in des]
print("Mensaje final: ",final_parts,"\n")

# Unir las partes para obtener el mensaje original  
decrypted_message = "".join(final_parts)
print("Mensaje unido: ", decrypted_message, "\n\n")

# Comparar hashes del mensaje original y descifrado
msg_hash = hashlib.sha256(msg.encode()).hexdigest()
decrypted_hash = hashlib.sha256(decrypted_message.encode()).hexdigest()

print("Hash original: ",msg_hash,"\n\nHash descifrado: ",decrypted_hash,"\n\n")
print("Los hashes","no" if (msg_hash != decrypted_hash) else "sí","coinciden.")

