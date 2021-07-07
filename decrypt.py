import os
import sys
import numpy as np
from Crypto.Cipher import AES

# Required Modules:
# pycryptodome
# numpy

# Key & IV:
# 8A AE 04 08 A0 7B 43 C0  AB 7C 5C EB BC 57 4F 23  .....{C..|\...O#  <-- key 16 bytes
# 11 22 33 44 55 A6 77 88  99 00 11 22 33 44 55 B6  ."3DU.w...."3DU.  <-- iv  16 bytes
# Key and IV are currently hardcoded into the Diagnostic utility. They should remain static.

# Events during Decryption & Decoding:
# First layer is an encryption. AES CBC Decryption with above key and iv. All encrypted files share same header format of ABBACDDCEFFE1221 and then filesize.
# Once decrypted, the second layer is an encoding / compression. The header is 3 blocks. The first block of the header represents a gate 
# (in binary, open / closed), as it gets reversed and signifies if decryption can proceed. But irrelevant for our purposes. Can just skip past. 
# second part is final extraxted file size, and also gets reversed, so ex. 000023dc becomes DC23 0000 (zeros not read). The third block is 
# unsure. but if you divide the first half of the third part eg 514C by the final extracted filesize from the second block, it leaves 0 remainder. 
# This remains true for all files. So must represent some sort of checksum during the encoding / compression process, but is not read at all 
# by diags during extraction. So can probably just be left as is or filled with random bytes during re-encryption.

# Rounds Calculation:
# take encrypted file size, which is the second block, ex. A40, 9E0, 790 in the encrypted enc file.
# take last byte from decrypted file, ex. 05, 0B
# rounds = (encrypted filesize) - (last byte from decrypted file)
# ex. A40 - 05 = A38
# round calculation (ex. A3B) is also the location where the terminator bit goes in the decrypted file
# so any padding at the end of the decrypted but non-decoded file is the amount used to subtract for rounds calculation, just repeated as padding

# regular enc files and data files use exactly same method
# diags.enc uses 7E rounds. Doesn't use regular rounds calculation.
	

def decrypt(encrypted_data, key, iv):
	mode = AES.MODE_CBC
	decryptor = AES.new(key, mode, IV=iv)
	decrypted_data = decryptor.decrypt(encrypted_data)
	return decrypted_data

def get_decrypted_filesize(decrypted_array):
	header1 = decrypted_array[7]
	header2 = decrypted_array[6]
	filesize = bytes([header1,header2])
	return filesize

def get_bytes(muteable_array, counter1, byte):
	byte2 = muteable_array[counter1]
	byte3 = ((int.from_bytes(byte2, 'little') & 0xF0) << 4) | int.from_bytes(byte, 'little')
	byte4 = (int.from_bytes(byte2, 'little') & 0xF) + 2
	return byte3, byte4

def scratchpad(mem_location, membuffer, sc_minimized, byte):
	if mem_location < 4096:
		membuffer[sc_minimized] = int.from_bytes(byte, 'little')
		mem_location += 1
	else:
		mem_location = 0
		membuffer[sc_minimized] = int.from_bytes(byte, 'little')
		mem_location += 1
	return membuffer, mem_location

def write_file(output_file, counter2, xor):
	with open(output_file, 'ab+') as write_file:
		write_file.seek(counter2,0)
		write_file.write(xor)
		write_file.close()

def xor(byte):
	xor = int.from_bytes(byte, 'little') ^ 0x80 #0x80 appears to be constant / static
	x = bytes([xor])
	return x

def main(in_file, out_file, round_option):

	# File to decrypt
	encfile = in_file
	
	# Get Key and iv from keyfile
	#keyfile = 'keyfile.bin'

	# Load Key and IV
	key = b'\x8A\xAE\x04\x08\xA0\x7B\x43\xC0\xAB\x7C\x5C\xEB\xBC\x57\x4F\x23'
	iv = b'\x11\x22\x33\x44\x55\xA6\x77\x88\x99\x00\x11\x22\x33\x44\x55\xB6'

	# Get Encrypted file
	with open(encfile, 'rb') as enc_file_in:
		enc_file_in.seek(8) 				# Seek to ENC size of data after header
		enc_size = enc_file_in.read(2) 		# Read ENC size
		enc_file_in.seek(16) 				# Seek past header info
		encrypted_data = enc_file_in.read() # Read the rest of the data from offset 16 to end of file
		enc_file_in.close()

	# Perform Decryption
	decrypted_data = decrypt(encrypted_data, key, iv)

	# Convert Decrypted Data into Array
	muteable_array = np.frombuffer(bytearray(decrypted_data), dtype=np.uint8, count=-1, offset=0)

	# Get Last Byte (required for Rounds Calculation)
	last_byte = bytes([muteable_array[-1]])

	# Rounds Calculation:
	if round_option == '-r':
		rounds = int.from_bytes(enc_size, 'little') - int.from_bytes(last_byte, 'little')
	elif round_option == '-d':
		rounds = 0x7E #for diags.enc
	#elif round_option == '-s':
		#rounds = 0x142FB # for SMART

	# Inject Terminator Byte:
	terminator_byte = int.from_bytes(b'\x00', 'little')
	muteable_array[rounds] = terminator_byte

	# Get Final Filesize of Decrypted and Decoded File
	filesize = get_decrypted_filesize(muteable_array)
	#filesize = int.to_bytes(0x142FB, 4, 'little') #For SMART, have to disable terminator byte and crtl C when at 83kb

	# Name of file that will be written to disk
	output_file = out_file

	# Remove output file if exists from previous attempt
	if os.path.exists(output_file):
		os.remove(output_file)

	#membuffer = np.empty(4096, dtype=np.uint16)
	membuffer = np.full(4096,20, dtype=np.uint8) #Create 4kb scratch area and fill scratch area with 20's
	mem_location = 4078 #starting mem offset in scratch area
	scratch_counter = 0xFEE #0xFEE = 4078, so represents start location in scratch area
	sc_minimized = 0xFEE
	local_74 = 0x00
	counter1 = 0x0C
	counter2 = 0 
	counter3 = 0
	write_filesize = b''

	# Decoding Process:
	# Translated from ASM . . . so kinda rough around the edges, but works!
	while write_filesize <= filesize: 
		
		local_74 = local_74 >> 1 #Right logical shift (Returns local_74 with the bits shifted to the right by 1 place) essential divides by 2
		
		if local_74 & 0x100 == 0: #bitwise AND. Each bit of the output is 1 if the corresponding bit of x AND of y is 1, otherwise it's 0. 
			
			if counter1 <= rounds:

				byte = muteable_array[counter1]
				counter1 += 1
				local_74 = int.from_bytes(byte, 'little') | 0xFF00

			else:

				break

			if local_74 & 1 != 0:

				if counter1 <= rounds:
					
					byte = muteable_array[counter1]
					
					counter1 += 1
					
					if counter2 < int.from_bytes(filesize, 'little'):
					
						x = xor(byte)
						write_file(output_file, counter2, x)
						counter2 += 1
						membuffer, mem_location = scratchpad(mem_location, membuffer, sc_minimized, byte)
						scratch_counter += 1 & 0xFFF
						sc_minimized = np.uint16(scratch_counter) & 0xFFF

					else:

						rbp_30h = 0x8000000000000005 #Error Code
						break
				else:

					break

			else:
			
				if counter1 <= rounds:

					byte = muteable_array[counter1]
					counter1 += 1

					if counter1 <= rounds:

						byte3, byte4 = get_bytes(muteable_array, counter1, byte)
						counter1 += 1
						counter3 = 0 

						while byte4 >= counter3:

							byte5 = (byte3 + counter3) & 0xFFF
							byte = membuffer[byte5]
							
							if counter2 < int.from_bytes(filesize, 'little'):
							
								x = xor(byte)
								write_file(output_file, counter2, x)
								counter2 += 1
								membuffer, mem_location = scratchpad(mem_location, membuffer, sc_minimized, byte)
								scratch_counter += 1 & 0xFFF
								sc_minimized = np.uint16(scratch_counter) & 0xFFF
								counter3 += 1

							else:
								rbp_30h = 0x8000000000000005 #Error Code

						else:
							#Filler
							empty = None

					else:

						break
				else:

					break

		else: #local_74 & 0x100 != 0:
			
			if local_74 & 1 == 0:
				
				if counter1 <= rounds:
					
					byte = muteable_array[counter1]
					counter1 += 1

					if counter1 <= rounds:

						byte3, byte4 = get_bytes(muteable_array, counter1, byte)
						counter1 += 1
						counter3 = 0

						while byte4 >= counter3:

							byte5 = (byte3 + counter3) & 0xFFF
							byte = membuffer[byte5]

							if counter2 < int.from_bytes(filesize, 'little'):
							
								x = xor(byte)
								write_file(output_file, counter2, x)
								counter2 += 1
								membuffer, mem_location = scratchpad(mem_location, membuffer, sc_minimized, byte)
								scratch_counter += 1 & 0xFFF
								sc_minimized = np.uint16(scratch_counter) & 0xFFF
								counter3 += 1

							else:
								
								rbp_30h = 0x8000000000000005 #Error Code

						else:
							#Filler
							empty = None

					else:
						#print ('Finished Rounds')
						break
				else:

					break

			else:
				if counter1 <= rounds:

					byte = muteable_array[counter1]
					counter1 += 1

					if counter2 < int.from_bytes(filesize, 'little'):
					
						x = xor(byte)
						write_file(output_file, counter2, x)
						counter2 += 1
						membuffer, mem_location = scratchpad(mem_location, membuffer, sc_minimized, byte)
						scratch_counter += 1 & 0xFFF
						sc_minimized = np.uint16(scratch_counter) & 0xFFF

					else:

						rbp_30h = 0x8000000000000005 #Error Code
						break

				else:

					break

		# Update size of writefile
		if os.path.exists(output_file):
			wfs = os.path.getsize(output_file)
			write_filesize = bytes(wfs)

in_file = sys.argv[1]
out_file = sys.argv[2]
round_option = sys.argv[3]
main(in_file, out_file, round_option)
