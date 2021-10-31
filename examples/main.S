
main.o:     file format elf64-x86-64


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
    1073:	4c 8d 05 36 04 00 00 	lea    0x436(%rip),%r8        # 14b0 <__libc_csu_fini>
    107a:	48 8d 0d bf 03 00 00 	lea    0x3bf(%rip),%rcx        # 1440 <__libc_csu_init>
    1081:	48 8d 3d 58 03 00 00 	lea    0x358(%rip),%rdi        # 13e0 <main>
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
    1178:	48 8d 0d b1 02 00 00 	lea    0x2b1(%rip),%rcx        # 1430 <__typeid__ZTSFviE_global_addr>
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

00000000000011a0 <second_gate_dup.cfi>:
    11a0:	55                   	push   %rbp
    11a1:	48 89 e5             	mov    %rsp,%rbp
    11a4:	48 83 ec 10          	sub    $0x10,%rsp
    11a8:	89 7d f8             	mov    %edi,-0x8(%rbp)
    11ab:	89 75 fc             	mov    %esi,-0x4(%rbp)
    11ae:	8b 45 f8             	mov    -0x8(%rbp),%eax
    11b1:	03 45 fc             	add    -0x4(%rbp),%eax
    11b4:	83 f8 00             	cmp    $0x0,%eax
    11b7:	74 24                	je     11dd <second_gate_dup.cfi+0x3d>
    11b9:	48 63 45 f8          	movslq -0x8(%rbp),%rax
    11bd:	48 8d 0d 8c 2e 00 00 	lea    0x2e8c(%rip),%rcx        # 4050 <un_init_func_table>
    11c4:	48 8b 04 c1          	mov    (%rcx,%rax,8),%rax
    11c8:	48 8d 0d 61 02 00 00 	lea    0x261(%rip),%rcx        # 1430 <__typeid__ZTSFviE_global_addr>
    11cf:	48 39 c8             	cmp    %rcx,%rax
    11d2:	74 02                	je     11d6 <second_gate_dup.cfi+0x36>
    11d4:	0f 0b                	ud2    
    11d6:	8b 7d fc             	mov    -0x4(%rbp),%edi
    11d9:	ff d0                	callq  *%rax
    11db:	eb 02                	jmp    11df <second_gate_dup.cfi+0x3f>
    11dd:	eb 00                	jmp    11df <second_gate_dup.cfi+0x3f>
    11df:	48 83 c4 10          	add    $0x10,%rsp
    11e3:	5d                   	pop    %rbp
    11e4:	c3                   	retq   
    11e5:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    11ec:	00 00 00 
    11ef:	90                   	nop

00000000000011f0 <target>:
    11f0:	55                   	push   %rbp
    11f1:	48 89 e5             	mov    %rsp,%rbp
    11f4:	48 83 ec 10          	sub    $0x10,%rsp
    11f8:	89 7d fc             	mov    %edi,-0x4(%rbp)
    11fb:	48 8d 3d 02 0e 00 00 	lea    0xe02(%rip),%rdi        # 2004 <_IO_stdin_used+0x4>
    1202:	b0 00                	mov    $0x0,%al
    1204:	e8 27 fe ff ff       	callq  1030 <printf@plt>
    1209:	48 83 c4 10          	add    $0x10,%rsp
    120d:	5d                   	pop    %rbp
    120e:	c3                   	retq   
    120f:	90                   	nop

0000000000001210 <origin_flow.cfi>:
    1210:	55                   	push   %rbp
    1211:	48 89 e5             	mov    %rsp,%rbp
    1214:	48 83 ec 10          	sub    $0x10,%rsp
    1218:	48 89 7d f0          	mov    %rdi,-0x10(%rbp)
    121c:	89 75 fc             	mov    %esi,-0x4(%rbp)
    121f:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
    1223:	8b 55 fc             	mov    -0x4(%rbp),%edx
    1226:	48 8d 3d e0 0d 00 00 	lea    0xde0(%rip),%rdi        # 200d <_IO_stdin_used+0xd>
    122d:	b0 00                	mov    $0x0,%al
    122f:	e8 fc fd ff ff       	callq  1030 <printf@plt>
    1234:	31 c0                	xor    %eax,%eax
    1236:	48 83 c4 10          	add    $0x10,%rsp
    123a:	5d                   	pop    %rbp
    123b:	c3                   	retq   
    123c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000001240 <first_gate.cfi>:
    1240:	55                   	push   %rbp
    1241:	48 89 e5             	mov    %rsp,%rbp
    1244:	48 83 ec 10          	sub    $0x10,%rsp
    1248:	48 89 7d f0          	mov    %rdi,-0x10(%rbp)
    124c:	89 75 fc             	mov    %esi,-0x4(%rbp)
    124f:	83 7d fc ff          	cmpl   $0xffffffff,-0x4(%rbp)
    1253:	75 09                	jne    125e <first_gate.cfi+0x1e>
    1255:	c7 45 f8 ff ff ff ff 	movl   $0xffffffff,-0x8(%rbp)
    125c:	eb 71                	jmp    12cf <first_gate.cfi+0x8f>
    125e:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
    1262:	75 30                	jne    1294 <first_gate.cfi+0x54>
    1264:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    1268:	48 8d 0d a1 01 00 00 	lea    0x1a1(%rip),%rcx        # 1410 <__typeid__ZTSFviiE_global_addr>
    126f:	48 89 c2             	mov    %rax,%rdx
    1272:	48 29 ca             	sub    %rcx,%rdx
    1275:	48 89 d1             	mov    %rdx,%rcx
    1278:	48 c1 e9 03          	shr    $0x3,%rcx
    127c:	48 c1 e2 3d          	shl    $0x3d,%rdx
    1280:	48 09 d1             	or     %rdx,%rcx
    1283:	48 83 f9 01          	cmp    $0x1,%rcx
    1287:	76 02                	jbe    128b <first_gate.cfi+0x4b>
    1289:	0f 0b                	ud2    
    128b:	8b 7d fc             	mov    -0x4(%rbp),%edi
    128e:	31 f6                	xor    %esi,%esi
    1290:	ff d0                	callq  *%rax
    1292:	eb 34                	jmp    12c8 <first_gate.cfi+0x88>
    1294:	48 8b 05 d5 2a 00 00 	mov    0x2ad5(%rip),%rax        # 3d70 <init_func_table>
    129b:	48 8d 0d 6e 01 00 00 	lea    0x16e(%rip),%rcx        # 1410 <__typeid__ZTSFviiE_global_addr>
    12a2:	48 89 c2             	mov    %rax,%rdx
    12a5:	48 29 ca             	sub    %rcx,%rdx
    12a8:	48 89 d1             	mov    %rdx,%rcx
    12ab:	48 c1 e9 03          	shr    $0x3,%rcx
    12af:	48 c1 e2 3d          	shl    $0x3d,%rdx
    12b3:	48 09 d1             	or     %rdx,%rcx
    12b6:	48 83 f9 01          	cmp    $0x1,%rcx
    12ba:	76 02                	jbe    12be <first_gate.cfi+0x7e>
    12bc:	0f 0b                	ud2    
    12be:	8b 7d fc             	mov    -0x4(%rbp),%edi
    12c1:	be ff ff ff ff       	mov    $0xffffffff,%esi
    12c6:	ff d0                	callq  *%rax
    12c8:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
    12cf:	8b 45 f8             	mov    -0x8(%rbp),%eax
    12d2:	48 83 c4 10          	add    $0x10,%rsp
    12d6:	5d                   	pop    %rbp
    12d7:	c3                   	retq   
    12d8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    12df:	00 

00000000000012e0 <third_gate.cfi>:
    12e0:	55                   	push   %rbp
    12e1:	48 89 e5             	mov    %rsp,%rbp
    12e4:	48 83 ec 10          	sub    $0x10,%rsp
    12e8:	89 7d fc             	mov    %edi,-0x4(%rbp)
    12eb:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
    12ef:	75 0a                	jne    12fb <third_gate.cfi+0x1b>
    12f1:	8b 7d fc             	mov    -0x4(%rbp),%edi
    12f4:	e8 f7 fe ff ff       	callq  11f0 <target>
    12f9:	eb 02                	jmp    12fd <third_gate.cfi+0x1d>
    12fb:	eb 00                	jmp    12fd <third_gate.cfi+0x1d>
    12fd:	48 83 c4 10          	add    $0x10,%rsp
    1301:	5d                   	pop    %rbp
    1302:	c3                   	retq   
    1303:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    130a:	00 00 00 
    130d:	0f 1f 00             	nopl   (%rax)

0000000000001310 <vuln>:
    1310:	55                   	push   %rbp
    1311:	48 89 e5             	mov    %rsp,%rbp
    1314:	48 83 ec 20          	sub    $0x20,%rsp
    1318:	48 8d 05 01 01 00 00 	lea    0x101(%rip),%rax        # 1420 <__typeid__ZTSFiPFviiEiE_global_addr>
    131f:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    1323:	48 8d 3d 09 0d 00 00 	lea    0xd09(%rip),%rdi        # 2033 <_IO_stdin_used+0x33>
    132a:	48 8d 35 f7 00 00 00 	lea    0xf7(%rip),%rsi        # 1428 <first_gate>
    1331:	48 8d 15 d8 00 00 00 	lea    0xd8(%rip),%rdx        # 1410 <__typeid__ZTSFviiE_global_addr>
    1338:	b0 00                	mov    $0x0,%al
    133a:	e8 f1 fc ff ff       	callq  1030 <printf@plt>
    133f:	48 8d 3d 12 0d 00 00 	lea    0xd12(%rip),%rdi        # 2058 <_IO_stdin_used+0x58>
    1346:	48 8d 75 e8          	lea    -0x18(%rbp),%rsi
    134a:	b0 00                	mov    $0x0,%al
    134c:	e8 ef fc ff ff       	callq  1040 <__isoc99_scanf@plt>
    1351:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
    1358:	00 
    1359:	48 8d 3d f8 0c 00 00 	lea    0xcf8(%rip),%rdi        # 2058 <_IO_stdin_used+0x58>
    1360:	48 8d 75 f0          	lea    -0x10(%rbp),%rsi
    1364:	b0 00                	mov    $0x0,%al
    1366:	e8 d5 fc ff ff       	callq  1040 <__isoc99_scanf@plt>
    136b:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    1372:	48 8d 3d e2 0c 00 00 	lea    0xce2(%rip),%rdi        # 205b <_IO_stdin_used+0x5b>
    1379:	48 8d 75 fc          	lea    -0x4(%rbp),%rsi
    137d:	b0 00                	mov    $0x0,%al
    137f:	e8 bc fc ff ff       	callq  1040 <__isoc99_scanf@plt>
    1384:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
    1388:	48 8d 05 91 00 00 00 	lea    0x91(%rip),%rax        # 1420 <__typeid__ZTSFiPFviiEiE_global_addr>
    138f:	48 89 ca             	mov    %rcx,%rdx
    1392:	48 29 c2             	sub    %rax,%rdx
    1395:	48 89 d0             	mov    %rdx,%rax
    1398:	48 c1 e8 03          	shr    $0x3,%rax
    139c:	48 c1 e2 3d          	shl    $0x3d,%rdx
    13a0:	48 09 d0             	or     %rdx,%rax
    13a3:	48 83 f8 01          	cmp    $0x1,%rax
    13a7:	76 02                	jbe    13ab <vuln+0x9b>
    13a9:	0f 0b                	ud2    
    13ab:	48 8b 7d f0          	mov    -0x10(%rbp),%rdi
    13af:	8b 75 fc             	mov    -0x4(%rbp),%esi
    13b2:	ff d1                	callq  *%rcx
    13b4:	48 83 c4 20          	add    $0x20,%rsp
    13b8:	5d                   	pop    %rbp
    13b9:	c3                   	retq   
    13ba:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

00000000000013c0 <init_table_on_runtime>:
    13c0:	55                   	push   %rbp
    13c1:	48 89 e5             	mov    %rsp,%rbp
    13c4:	48 8d 05 65 00 00 00 	lea    0x65(%rip),%rax        # 1430 <__typeid__ZTSFviE_global_addr>
    13cb:	48 89 05 7e 2c 00 00 	mov    %rax,0x2c7e(%rip)        # 4050 <un_init_func_table>
    13d2:	5d                   	pop    %rbp
    13d3:	c3                   	retq   
    13d4:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    13db:	00 00 00 
    13de:	66 90                	xchg   %ax,%ax

00000000000013e0 <main>:
    13e0:	55                   	push   %rbp
    13e1:	48 89 e5             	mov    %rsp,%rbp
    13e4:	48 83 ec 10          	sub    $0x10,%rsp
    13e8:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    13ef:	e8 cc ff ff ff       	callq  13c0 <init_table_on_runtime>
    13f4:	31 ff                	xor    %edi,%edi
    13f6:	31 f6                	xor    %esi,%esi
    13f8:	e8 a3 fd ff ff       	callq  11a0 <second_gate_dup.cfi>
    13fd:	e8 0e ff ff ff       	callq  1310 <vuln>
    1402:	31 c0                	xor    %eax,%eax
    1404:	48 83 c4 10          	add    $0x10,%rsp
    1408:	5d                   	pop    %rbp
    1409:	c3                   	retq   
    140a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000001410 <__typeid__ZTSFviiE_global_addr>:
    1410:	e9 3b fd ff ff       	jmpq   1150 <second_gate.cfi>
    1415:	cc                   	int3   
    1416:	cc                   	int3   
    1417:	cc                   	int3   

0000000000001418 <second_gate_dup>:
    1418:	e9 83 fd ff ff       	jmpq   11a0 <second_gate_dup.cfi>
    141d:	cc                   	int3   
    141e:	cc                   	int3   
    141f:	cc                   	int3   

0000000000001420 <__typeid__ZTSFiPFviiEiE_global_addr>:
    1420:	e9 eb fd ff ff       	jmpq   1210 <origin_flow.cfi>
    1425:	cc                   	int3   
    1426:	cc                   	int3   
    1427:	cc                   	int3   

0000000000001428 <first_gate>:
    1428:	e9 13 fe ff ff       	jmpq   1240 <first_gate.cfi>
    142d:	cc                   	int3   
    142e:	cc                   	int3   
    142f:	cc                   	int3   

0000000000001430 <__typeid__ZTSFviE_global_addr>:
    1430:	e9 ab fe ff ff       	jmpq   12e0 <third_gate.cfi>
    1435:	cc                   	int3   
    1436:	cc                   	int3   
    1437:	cc                   	int3   
    1438:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    143f:	00 

0000000000001440 <__libc_csu_init>:
    1440:	f3 0f 1e fa          	endbr64 
    1444:	41 57                	push   %r15
    1446:	4c 8d 3d 13 29 00 00 	lea    0x2913(%rip),%r15        # 3d60 <__frame_dummy_init_array_entry>
    144d:	41 56                	push   %r14
    144f:	49 89 d6             	mov    %rdx,%r14
    1452:	41 55                	push   %r13
    1454:	49 89 f5             	mov    %rsi,%r13
    1457:	41 54                	push   %r12
    1459:	41 89 fc             	mov    %edi,%r12d
    145c:	55                   	push   %rbp
    145d:	48 8d 2d 04 29 00 00 	lea    0x2904(%rip),%rbp        # 3d68 <__do_global_dtors_aux_fini_array_entry>
    1464:	53                   	push   %rbx
    1465:	4c 29 fd             	sub    %r15,%rbp
    1468:	48 83 ec 08          	sub    $0x8,%rsp
    146c:	e8 8f fb ff ff       	callq  1000 <_init>
    1471:	48 c1 fd 03          	sar    $0x3,%rbp
    1475:	74 1f                	je     1496 <__libc_csu_init+0x56>
    1477:	31 db                	xor    %ebx,%ebx
    1479:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1480:	4c 89 f2             	mov    %r14,%rdx
    1483:	4c 89 ee             	mov    %r13,%rsi
    1486:	44 89 e7             	mov    %r12d,%edi
    1489:	41 ff 14 df          	callq  *(%r15,%rbx,8)
    148d:	48 83 c3 01          	add    $0x1,%rbx
    1491:	48 39 dd             	cmp    %rbx,%rbp
    1494:	75 ea                	jne    1480 <__libc_csu_init+0x40>
    1496:	48 83 c4 08          	add    $0x8,%rsp
    149a:	5b                   	pop    %rbx
    149b:	5d                   	pop    %rbp
    149c:	41 5c                	pop    %r12
    149e:	41 5d                	pop    %r13
    14a0:	41 5e                	pop    %r14
    14a2:	41 5f                	pop    %r15
    14a4:	c3                   	retq   
    14a5:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
    14ac:	00 00 00 00 

00000000000014b0 <__libc_csu_fini>:
    14b0:	f3 0f 1e fa          	endbr64 
    14b4:	c3                   	retq   

Disassembly of section .fini:

00000000000014b8 <_fini>:
    14b8:	f3 0f 1e fa          	endbr64 
    14bc:	48 83 ec 08          	sub    $0x8,%rsp
    14c0:	48 83 c4 08          	add    $0x8,%rsp
    14c4:	c3                   	retq   
