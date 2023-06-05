import wave
import audioop
from main import Encrypt

rc5 = Encrypt(32, 12, b'\xDC\x49\xDB\x13\x75\xA5\x58\x4F\x64\x85\xB4\x13\xB5\xF1\x2B\xAF')

rc5.encryptFile("impact.wav", "out2.dacd")
print("great")
rc5.encryptFile("out2.dacd", "test1.wav")

audio = wave.open("loop.wav")
audio1 = wave.open("test.wav")

print((audio1.readframes(audio1.getnframes())) == audio.readframes(audio.getnframes()))
