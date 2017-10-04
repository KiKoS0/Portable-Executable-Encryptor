[bits 32]
[org 0xFFFFFFFF] ; Section origin

push eax
push esi
push edi
push ecx
push ebx
lea edi,[0xFFFFFFFF] ; Section to decrypt 
mov esi,edi
mov ecx,0xFFFFFFFF  ; Size of the section to decrypt
mov bl,0xFF         ; Decryption Key
cld
decrypt:
	lodsb
	xor al,bl
	inc bl
	stosb
	loop decrypt

pop ebx
pop ecx
pop edi
pop esi
pop eax

jmp 0xFFFFFFFF  ; Old Entry point


	

