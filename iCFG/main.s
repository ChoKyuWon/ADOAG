
../examples/main.o:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64 
    1004:	48 83 ec 08          	sub    $0x8,%rsp
    1008:	48 8b 05 d1 2f 00 00 	mov    0x2fd1(%rip),%rax        # 3fe0 <__gmon_start__>
    100f:	48 85 c0             	test   %rax,%rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	callq  *%rax
    1016:	48 83 c4 08          	add    $0x8,%rsp
    101a:	c3                   	retq   

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 e2 2f 00 00    	pushq  0x2fe2(%rip)        # 4008 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	ff 25 e4 2f 00 00    	jmpq   *0x2fe4(%rip)        # 4010 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000001030 <printf@plt>:
    1030:	ff 25 e2 2f 00 00    	jmpq   *0x2fe2(%rip)        # 4018 <printf@GLIBC_2.2.5>
    1036:	68 00 00 00 00       	pushq  $0x0
    103b:	e9 e0 ff ff ff       	jmpq   1020 <.plt>

0000000000001040 <__isoc99_scanf@plt>:
    1040:	ff 25 da 2f 00 00    	jmpq   *0x2fda(%rip)        # 4020 <__isoc99_scanf@GLIBC_2.7>
    1046:	68 01 00 00 00       	pushq  $0x1
    104b:	e9 d0 ff ff ff       	jmpq   1020 <.plt>

Disassembly of section .plt.got:

0000000000001050 <__cxa_finalize@plt>:
    1050:	ff 25 9a 2f 00 00    	jmpq   *0x2f9a(%rip)        # 3ff0 <__cxa_finalize@GLIBC_2.2.5>
    1056:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

0000000000001060 <_start>:
    1060:	f3 0f 1e fa          	endbr64 
    1064:	31 ed                	xor    %ebp,%ebp
    1066:	49 89 d1             	mov    %rdx,%r9
    1069:	5e                   	pop    %rsi
    106a:	48 89 e2             	mov    %rsp,%rdx
    106d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    1071:	50                   	push   %rax
    1072:	54                   	push   %rsp
    1073:	4c 8d 05 b6 03 00 00 	lea    0x3b6(%rip),%r8        # 1430 <__libc_csu_fini>
    107a:	48 8d 0d 3f 03 00 00 	lea    0x33f(%rip),%rcx        # 13c0 <__libc_csu_init>
    1081:	48 8d 3d d8 02 00 00 	lea    0x2d8(%rip),%rdi        # 1360 <main>
    1088:	ff 15 4a 2f 00 00    	callq  *0x2f4a(%rip)        # 3fd8 <__libc_start_main@GLIBC_2.2.5>
    108e:	f4                   	hlt    
    108f:	90                   	nop

0000000000001090 <deregister_tm_clones>:
    1090:	48 8d 3d a1 2f 00 00 	lea    0x2fa1(%rip),%rdi        # 4038 <__TMC_END__>
    1097:	48 8d 05 9a 2f 00 00 	lea    0x2f9a(%rip),%rax        # 4038 <__TMC_END__>
    109e:	48 39 f8             	cmp    %rdi,%rax
    10a1:	74 15                	je     10b8 <deregister_tm_clones+0x28>
    10a3:	48 8b 05 26 2f 00 00 	mov    0x2f26(%rip),%rax        # 3fd0 <_ITM_deregisterTMCloneTable>
    10aa:	48 85 c0             	test   %rax,%rax
    10ad:	74 09                	je     10b8 <deregister_tm_clones+0x28>
    10af:	ff e0                	jmpq   *%rax
    10b1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    10b8:	c3                   	retq   
    10b9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000010c0 <register_tm_clones>:
    10c0:	48 8d 3d 71 2f 00 00 	lea    0x2f71(%rip),%rdi        # 4038 <__TMC_END__>
    10c7:	48 8d 35 6a 2f 00 00 	lea    0x2f6a(%rip),%rsi        # 4038 <__TMC_END__>
    10ce:	48 29 fe             	sub    %rdi,%rsi
    10d1:	48 89 f0             	mov    %rsi,%rax
    10d4:	48 c1 ee 3f          	shr    $0x3f,%rsi
    10d8:	48 c1 f8 03          	sar    $0x3,%rax
    10dc:	48 01 c6             	add    %rax,%rsi
    10df:	48 d1 fe             	sar    %rsi
    10e2:	74 14                	je     10f8 <register_tm_clones+0x38>
    10e4:	48 8b 05 fd 2e 00 00 	mov    0x2efd(%rip),%rax        # 3fe8 <_ITM_registerTMCloneTable>
    10eb:	48 85 c0             	test   %rax,%rax
    10ee:	74 08                	je     10f8 <register_tm_clones+0x38>
    10f0:	ff e0                	jmpq   *%rax
    10f2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    10f8:	c3                   	retq   
    10f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001100 <__do_global_dtors_aux>:
    1100:	f3 0f 1e fa          	endbr64 
    1104:	80 3d 35 2f 00 00 00 	cmpb   $0x0,0x2f35(%rip)        # 4040 <completed.0>
    110b:	75 2b                	jne    1138 <__do_global_dtors_aux+0x38>
    110d:	55                   	push   %rbp
    110e:	48 83 3d da 2e 00 00 	cmpq   $0x0,0x2eda(%rip)        # 3ff0 <__cxa_finalize@GLIBC_2.2.5>
    1115:	00 
    1116:	48 89 e5             	mov    %rsp,%rbp
    1119:	74 0c                	je     1127 <__do_global_dtors_aux+0x27>
    111b:	48 8b 3d 0e 2f 00 00 	mov    0x2f0e(%rip),%rdi        # 4030 <__dso_handle>
    1122:	e8 29 ff ff ff       	callq  1050 <__cxa_finalize@plt>
    1127:	e8 64 ff ff ff       	callq  1090 <deregister_tm_clones>
    112c:	c6 05 0d 2f 00 00 01 	movb   $0x1,0x2f0d(%rip)        # 4040 <completed.0>
    1133:	5d                   	pop    %rbp
    1134:	c3                   	retq   
    1135:	0f 1f 00             	nopl   (%rax)
    1138:	c3                   	retq   
    1139:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001140 <frame_dummy>:
    1140:	f3 0f 1e fa          	endbr64 
    1144:	e9 77 ff ff ff       	jmpq   10c0 <register_tm_clones>
    1149:	0f 1f 00             	nopl   (%rax)
    114c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000001150 <second_gate.cfi>:
    1150:	55                   	push   %rbp
    1151:	48 89 e5             	mov    %rsp,%rbp
    1154:	48 83 ec 10          	sub    $0x10,%rsp
    1158:	89 7d f8             	mov    %edi,-0x8(%rbp)
    115b:	89 75 fc             	mov    %esi,-0x4(%rbp)
    115e:	8b 45 f8             	mov    -0x8(%rbp),%eax
    1161:	03 45 fc             	add    -0x4(%rbp),%eax
    1164:	83 f8 00             	cmp    $0x0,%eax
    1167:	75 24                	jne    118d <second_gate.cfi+0x3d>
    1169:	48 63 45 f8          	movslq -0x8(%rbp),%rax
    116d:	48 8d 0d dc 2e 00 00 	lea    0x2edc(%rip),%rcx        # 4050 <un_init_func_table>
    1174:	48 8b 04 c1          	mov    (%rcx,%rax,8),%rax
    1178:	48 8d 0d 31 02 00 00 	lea    0x231(%rip),%rcx        # 13b0 <__typeid__ZTSFviE_global_addr>
    117f:	48 39 c8             	cmp    %rcx,%rax
    1182:	74 02                	je     1186 <second_gate.cfi+0x36>
    1184:	0f 0b                	ud2    
    1186:	8b 7d fc             	mov    -0x4(%rbp),%edi
    1189:	ff d0                	callq  *%rax
    118b:	eb 02                	jmp    118f <second_gate.cfi+0x3f>
    118d:	eb 00                	jmp    118f <second_gate.cfi+0x3f>
    118f:	48 83 c4 10          	add    $0x10,%rsp
    1193:	5d                   	pop    %rbp
    1194:	c3                   	retq   
    1195:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    119c:	00 00 00 
    119f:	90                   	nop

00000000000011a0 <target>:
    11a0:	55                   	push   %rbp
    11a1:	48 89 e5             	mov    %rsp,%rbp
    11a4:	48 83 ec 10          	sub    $0x10,%rsp
    11a8:	89 7d fc             	mov    %edi,-0x4(%rbp)
    11ab:	48 8d 3d 52 0e 00 00 	lea    0xe52(%rip),%rdi        # 2004 <_IO_stdin_used+0x4>
    11b2:	b0 00                	mov    $0x0,%al
    11b4:	e8 77 fe ff ff       	callq  1030 <printf@plt>
    11b9:	48 83 c4 10          	add    $0x10,%rsp
    11bd:	5d                   	pop    %rbp
    11be:	c3                   	retq   
    11bf:	90                   	nop

00000000000011c0 <origin_flow.cfi>:
    11c0:	55                   	push   %rbp
    11c1:	48 89 e5             	mov    %rsp,%rbp
    11c4:	48 83 ec 10          	sub    $0x10,%rsp
    11c8:	48 89 7d f0          	mov    %rdi,-0x10(%rbp)
    11cc:	89 75 fc             	mov    %esi,-0x4(%rbp)
    11cf:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    11d3:	8b 55 fc             	mov    -0x4(%rbp),%edx
    11d6:	48 8d 3d 30 0e 00 00 	lea    0xe30(%rip),%rdi        # 200d <_IO_stdin_used+0xd>
    11dd:	b0 00                	mov    $0x0,%al
    11df:	e8 4c fe ff ff       	callq  1030 <printf@plt>
    11e4:	31 c0                	xor    %eax,%eax
    11e6:	48 83 c4 10          	add    $0x10,%rsp
    11ea:	5d                   	pop    %rbp
    11eb:	c3                   	retq   
    11ec:	0f 1f 40 00          	nopl   0x0(%rax)

00000000000011f0 <first_gate.cfi>:
    11f0:	55                   	push   %rbp
    11f1:	48 89 e5             	mov    %rsp,%rbp
    11f4:	48 83 ec 10          	sub    $0x10,%rsp
    11f8:	48 89 7d f0          	mov    %rdi,-0x10(%rbp)
    11fc:	89 75 fc             	mov    %esi,-0x4(%rbp)
    11ff:	83 7d fc ff          	cmpl   $0xffffffff,-0x4(%rbp)
    1203:	75 09                	jne    120e <first_gate.cfi+0x1e>
    1205:	c7 45 f8 ff ff ff ff 	movl   $0xffffffff,-0x8(%rbp)
    120c:	eb 47                	jmp    1255 <first_gate.cfi+0x65>
    120e:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
    1212:	75 1b                	jne    122f <first_gate.cfi+0x3f>
    1214:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1218:	48 8d 0d 71 01 00 00 	lea    0x171(%rip),%rcx        # 1390 <__typeid__ZTSFviiE_global_addr>
    121f:	48 39 c8             	cmp    %rcx,%rax
    1222:	74 02                	je     1226 <first_gate.cfi+0x36>
    1224:	0f 0b                	ud2    
    1226:	8b 7d fc             	mov    -0x4(%rbp),%edi
    1229:	31 f6                	xor    %esi,%esi
    122b:	ff d0                	callq  *%rax
    122d:	eb 1f                	jmp    124e <first_gate.cfi+0x5e>
    122f:	48 8b 05 3a 2b 00 00 	mov    0x2b3a(%rip),%rax        # 3d70 <init_func_table>
    1236:	48 8d 0d 53 01 00 00 	lea    0x153(%rip),%rcx        # 1390 <__typeid__ZTSFviiE_global_addr>
    123d:	48 39 c8             	cmp    %rcx,%rax
    1240:	74 02                	je     1244 <first_gate.cfi+0x54>
    1242:	0f 0b                	ud2    
    1244:	8b 7d fc             	mov    -0x4(%rbp),%edi
    1247:	be ff ff ff ff       	mov    $0xffffffff,%esi
    124c:	ff d0                	callq  *%rax
    124e:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
    1255:	8b 45 f8             	mov    -0x8(%rbp),%eax
    1258:	48 83 c4 10          	add    $0x10,%rsp
    125c:	5d                   	pop    %rbp
    125d:	c3                   	retq   
    125e:	66 90                	xchg   %ax,%ax

0000000000001260 <third_gate.cfi>:
    1260:	55                   	push   %rbp
    1261:	48 89 e5             	mov    %rsp,%rbp
    1264:	48 83 ec 10          	sub    $0x10,%rsp
    1268:	89 7d fc             	mov    %edi,-0x4(%rbp)
    126b:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
    126f:	75 0a                	jne    127b <third_gate.cfi+0x1b>
    1271:	8b 7d fc             	mov    -0x4(%rbp),%edi
    1274:	e8 27 ff ff ff       	callq  11a0 <target>
    1279:	eb 02                	jmp    127d <third_gate.cfi+0x1d>
    127b:	eb 00                	jmp    127d <third_gate.cfi+0x1d>
    127d:	48 83 c4 10          	add    $0x10,%rsp
    1281:	5d                   	pop    %rbp
    1282:	c3                   	retq   
    1283:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    128a:	00 00 00 
    128d:	0f 1f 00             	nopl   (%rax)

0000000000001290 <vuln>:
    1290:	55                   	push   %rbp
    1291:	48 89 e5             	mov    %rsp,%rbp
    1294:	48 83 ec 20          	sub    $0x20,%rsp
    1298:	48 8d 05 01 01 00 00 	lea    0x101(%rip),%rax        # 13a0 <__typeid__ZTSFiPFviiEiE_global_addr>
    129f:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    12a3:	48 8d 3d 89 0d 00 00 	lea    0xd89(%rip),%rdi        # 2033 <_IO_stdin_used+0x33>
    12aa:	48 8d 35 f7 00 00 00 	lea    0xf7(%rip),%rsi        # 13a8 <first_gate>
    12b1:	48 8d 15 d8 00 00 00 	lea    0xd8(%rip),%rdx        # 1390 <__typeid__ZTSFviiE_global_addr>
    12b8:	b0 00                	mov    $0x0,%al
    12ba:	e8 71 fd ff ff       	callq  1030 <printf@plt>
    12bf:	48 8d 3d 96 0d 00 00 	lea    0xd96(%rip),%rdi        # 205c <_IO_stdin_used+0x5c>
    12c6:	48 8d 75 e8          	lea    -0x18(%rbp),%rsi
    12ca:	b0 00                	mov    $0x0,%al
    12cc:	e8 6f fd ff ff       	callq  1040 <__isoc99_scanf@plt>
    12d1:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    12d8:	00 
    12d9:	48 8d 3d 7c 0d 00 00 	lea    0xd7c(%rip),%rdi        # 205c <_IO_stdin_used+0x5c>
    12e0:	48 8d 75 f0          	lea    -0x10(%rbp),%rsi
    12e4:	b0 00                	mov    $0x0,%al
    12e6:	e8 55 fd ff ff       	callq  1040 <__isoc99_scanf@plt>
    12eb:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    12f2:	48 8d 3d 68 0d 00 00 	lea    0xd68(%rip),%rdi        # 2061 <_IO_stdin_used+0x61>
    12f9:	48 8d 75 fc          	lea    -0x4(%rbp),%rsi
    12fd:	b0 00                	mov    $0x0,%al
    12ff:	e8 3c fd ff ff       	callq  1040 <__isoc99_scanf@plt>
    1304:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    1308:	48 8d 05 91 00 00 00 	lea    0x91(%rip),%rax        # 13a0 <__typeid__ZTSFiPFviiEiE_global_addr>
    130f:	48 89 ca             	mov    %rcx,%rdx
    1312:	48 29 c2             	sub    %rax,%rdx
    1315:	48 89 d0             	mov    %rdx,%rax
    1318:	48 c1 e8 03          	shr    $0x3,%rax
    131c:	48 c1 e2 3d          	shl    $0x3d,%rdx
    1320:	48 09 d0             	or     %rdx,%rax
    1323:	48 83 f8 01          	cmp    $0x1,%rax
    1327:	76 02                	jbe    132b <vuln+0x9b>
    1329:	0f 0b                	ud2    
    132b:	48 8b 7d f0          	mov    -0x10(%rbp),%rdi
    132f:	8b 75 fc             	mov    -0x4(%rbp),%esi
    1332:	ff d1                	callq  *%rcx
    1334:	48 83 c4 20          	add    $0x20,%rsp
    1338:	5d                   	pop    %rbp
    1339:	c3                   	retq   
    133a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000001340 <init_table_on_runtime>:
    1340:	55                   	push   %rbp
    1341:	48 89 e5             	mov    %rsp,%rbp
    1344:	48 8d 05 65 00 00 00 	lea    0x65(%rip),%rax        # 13b0 <__typeid__ZTSFviE_global_addr>
    134b:	48 89 05 fe 2c 00 00 	mov    %rax,0x2cfe(%rip)        # 4050 <un_init_func_table>
    1352:	5d                   	pop    %rbp
    1353:	c3                   	retq   
    1354:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    135b:	00 00 00 
    135e:	66 90                	xchg   %ax,%ax

0000000000001360 <main>:
    1360:	55                   	push   %rbp
    1361:	48 89 e5             	mov    %rsp,%rbp
    1364:	48 83 ec 10          	sub    $0x10,%rsp
    1368:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    136f:	e8 cc ff ff ff       	callq  1340 <init_table_on_runtime>
    1374:	e8 17 ff ff ff       	callq  1290 <vuln>
    1379:	31 c0                	xor    %eax,%eax
    137b:	48 83 c4 10          	add    $0x10,%rsp
    137f:	5d                   	pop    %rbp
    1380:	c3                   	retq   
    1381:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    1388:	00 00 00 
    138b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001390 <__typeid__ZTSFviiE_global_addr>:
    1390:	e9 bb fd ff ff       	jmpq   1150 <second_gate.cfi>
    1395:	cc                   	int3   
    1396:	cc                   	int3   
    1397:	cc                   	int3   
    1398:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    139f:	00 

00000000000013a0 <__typeid__ZTSFiPFviiEiE_global_addr>:
    13a0:	e9 1b fe ff ff       	jmpq   11c0 <origin_flow.cfi>
    13a5:	cc                   	int3   
    13a6:	cc                   	int3   
    13a7:	cc                   	int3   

00000000000013a8 <first_gate>:
    13a8:	e9 43 fe ff ff       	jmpq   11f0 <first_gate.cfi>
    13ad:	cc                   	int3   
    13ae:	cc                   	int3   
    13af:	cc                   	int3   

00000000000013b0 <__typeid__ZTSFviE_global_addr>:
    13b0:	e9 ab fe ff ff       	jmpq   1260 <third_gate.cfi>
    13b5:	cc                   	int3   
    13b6:	cc                   	int3   
    13b7:	cc                   	int3   
    13b8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    13bf:	00 

00000000000013c0 <__libc_csu_init>:
    13c0:	f3 0f 1e fa          	endbr64 
    13c4:	41 57                	push   %r15
    13c6:	4c 8d 3d 93 29 00 00 	lea    0x2993(%rip),%r15        # 3d60 <__frame_dummy_init_array_entry>
    13cd:	41 56                	push   %r14
    13cf:	49 89 d6             	mov    %rdx,%r14
    13d2:	41 55                	push   %r13
    13d4:	49 89 f5             	mov    %rsi,%r13
    13d7:	41 54                	push   %r12
    13d9:	41 89 fc             	mov    %edi,%r12d
    13dc:	55                   	push   %rbp
    13dd:	48 8d 2d 84 29 00 00 	lea    0x2984(%rip),%rbp        # 3d68 <__do_global_dtors_aux_fini_array_entry>
    13e4:	53                   	push   %rbx
    13e5:	4c 29 fd             	sub    %r15,%rbp
    13e8:	48 83 ec 08          	sub    $0x8,%rsp
    13ec:	e8 0f fc ff ff       	callq  1000 <_init>
    13f1:	48 c1 fd 03          	sar    $0x3,%rbp
    13f5:	74 1f                	je     1416 <__libc_csu_init+0x56>
    13f7:	31 db                	xor    %ebx,%ebx
    13f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1400:	4c 89 f2             	mov    %r14,%rdx
    1403:	4c 89 ee             	mov    %r13,%rsi
    1406:	44 89 e7             	mov    %r12d,%edi
    1409:	41 ff 14 df          	callq  *(%r15,%rbx,8)
    140d:	48 83 c3 01          	add    $0x1,%rbx
    1411:	48 39 dd             	cmp    %rbx,%rbp
    1414:	75 ea                	jne    1400 <__libc_csu_init+0x40>
    1416:	48 83 c4 08          	add    $0x8,%rsp
    141a:	5b                   	pop    %rbx
    141b:	5d                   	pop    %rbp
    141c:	41 5c                	pop    %r12
    141e:	41 5d                	pop    %r13
    1420:	41 5e                	pop    %r14
    1422:	41 5f                	pop    %r15
    1424:	c3                   	retq   
    1425:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    142c:	00 00 00 00 

0000000000001430 <__libc_csu_fini>:
    1430:	f3 0f 1e fa          	endbr64 
    1434:	c3                   	retq   

Disassembly of section .fini:

0000000000001438 <_fini>:
    1438:	f3 0f 1e fa          	endbr64 
    143c:	48 83 ec 08          	sub    $0x8,%rsp
    1440:	48 83 c4 08          	add    $0x8,%rsp
    1444:	c3                   	retq   
