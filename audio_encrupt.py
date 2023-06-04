import wave
import audioop
from main import Encrypt

# MAIN FILE

rc5 = Encrypt(32, 12, b'\x91\x5F\x46\x19\xBE\x41\xB2\x51\x63\x55\xA5\x01\x10\xA9\xCE\x91')

rc5.encryptFile('loop.wav', "out.txt")
rc5.decryptFile("out.txt", "test.wav")

audio = wave.open("loop.wav")
audio1 = wave.open("test.wav")

print((audio1.readframes(audio1.getnframes())) == audio.readframes(audio.getnframes()))
