
main.o:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <_init>:
  401000:	f3 0f 1e fa          	endbr64 
  401004:	48 83 ec 08          	sub    $0x8,%rsp
  401008:	48 8b 05 e9 2f 00 00 	mov    0x2fe9(%rip),%rax        # 403ff8 <__gmon_start__>
  40100f:	48 85 c0             	test   %rax,%rax
  401012:	74 02                	je     401016 <_init+0x16>
  401014:	ff d0                	callq  *%rax
  401016:	48 83 c4 08          	add    $0x8,%rsp
  40101a:	c3                   	retq   

Disassembly of section .plt:

0000000000401020 <.plt>:
  401020:	ff 35 e2 2f 00 00    	pushq  0x2fe2(%rip)        # 404008 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:	ff 25 e4 2f 00 00    	jmpq   *0x2fe4(%rip)        # 404010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000401030 <printf@plt>:
  401030:	ff 25 e2 2f 00 00    	jmpq   *0x2fe2(%rip)        # 404018 <printf@GLIBC_2.2.5>
  401036:	68 00 00 00 00       	pushq  $0x0
  40103b:	e9 e0 ff ff ff       	jmpq   401020 <.plt>

0000000000401040 <__isoc99_scanf@plt>:
  401040:	ff 25 da 2f 00 00    	jmpq   *0x2fda(%rip)        # 404020 <__isoc99_scanf@GLIBC_2.7>
  401046:	68 01 00 00 00       	pushq  $0x1
  40104b:	e9 d0 ff ff ff       	jmpq   401020 <.plt>

Disassembly of section .text:

0000000000401050 <_start>:
  401050:	f3 0f 1e fa          	endbr64 
  401054:	31 ed                	xor    %ebp,%ebp
  401056:	49 89 d1             	mov    %rdx,%r9
  401059:	5e                   	pop    %rsi
  40105a:	48 89 e2             	mov    %rsp,%rdx
  40105d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  401061:	50                   	push   %rax
  401062:	54                   	push   %rsp
  401063:	49 c7 c0 d0 14 40 00 	mov    $0x4014d0,%r8
  40106a:	48 c7 c1 60 14 40 00 	mov    $0x401460,%rcx
  401071:	48 c7 c7 00 14 40 00 	mov    $0x401400,%rdi
  401078:	ff 15 72 2f 00 00    	callq  *0x2f72(%rip)        # 403ff0 <__libc_start_main@GLIBC_2.2.5>
  40107e:	f4                   	hlt    
  40107f:	90                   	nop

0000000000401080 <_dl_relocate_static_pie>:
  401080:	f3 0f 1e fa          	endbr64 
  401084:	c3                   	retq   
  401085:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40108c:	00 00 00 
  40108f:	90                   	nop

0000000000401090 <deregister_tm_clones>:
  401090:	b8 38 40 40 00       	mov    $0x404038,%eax
  401095:	48 3d 38 40 40 00    	cmp    $0x404038,%rax
  40109b:	74 13                	je     4010b0 <deregister_tm_clones+0x20>
  40109d:	b8 00 00 00 00       	mov    $0x0,%eax
  4010a2:	48 85 c0             	test   %rax,%rax
  4010a5:	74 09                	je     4010b0 <deregister_tm_clones+0x20>
  4010a7:	bf 38 40 40 00       	mov    $0x404038,%edi
  4010ac:	ff e0                	jmpq   *%rax
  4010ae:	66 90                	xchg   %ax,%ax
  4010b0:	c3                   	retq   
  4010b1:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
  4010b8:	00 00 00 00 
  4010bc:	0f 1f 40 00          	nopl   0x0(%rax)

00000000004010c0 <register_tm_clones>:
  4010c0:	be 38 40 40 00       	mov    $0x404038,%esi
  4010c5:	48 81 ee 38 40 40 00 	sub    $0x404038,%rsi
  4010cc:	48 89 f0             	mov    %rsi,%rax
  4010cf:	48 c1 ee 3f          	shr    $0x3f,%rsi
  4010d3:	48 c1 f8 03          	sar    $0x3,%rax
  4010d7:	48 01 c6             	add    %rax,%rsi
  4010da:	48 d1 fe             	sar    %rsi
  4010dd:	74 11                	je     4010f0 <register_tm_clones+0x30>
  4010df:	b8 00 00 00 00       	mov    $0x0,%eax
  4010e4:	48 85 c0             	test   %rax,%rax
  4010e7:	74 07                	je     4010f0 <register_tm_clones+0x30>
  4010e9:	bf 38 40 40 00       	mov    $0x404038,%edi
  4010ee:	ff e0                	jmpq   *%rax
  4010f0:	c3                   	retq   
  4010f1:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
  4010f8:	00 00 00 00 
  4010fc:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000401100 <__do_global_dtors_aux>:
  401100:	f3 0f 1e fa          	endbr64 
  401104:	80 3d 35 2f 00 00 00 	cmpb   $0x0,0x2f35(%rip)        # 404040 <completed.0>
  40110b:	75 13                	jne    401120 <__do_global_dtors_aux+0x20>
  40110d:	55                   	push   %rbp
  40110e:	48 89 e5             	mov    %rsp,%rbp
  401111:	e8 7a ff ff ff       	callq  401090 <deregister_tm_clones>
  401116:	c6 05 23 2f 00 00 01 	movb   $0x1,0x2f23(%rip)        # 404040 <completed.0>
  40111d:	5d                   	pop    %rbp
  40111e:	c3                   	retq   
  40111f:	90                   	nop
  401120:	c3                   	retq   
  401121:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
  401128:	00 00 00 00 
  40112c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000401130 <frame_dummy>:
  401130:	f3 0f 1e fa          	endbr64 
  401134:	eb 8a                	jmp    4010c0 <register_tm_clones>
  401136:	66 90                	xchg   %ax,%ax
  401138:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  40113f:	00 

0000000000401140 <second_gate.cfi>:
  401140:	55                   	push   %rbp
  401141:	48 89 e5             	mov    %rsp,%rbp
  401144:	48 83 ec 10          	sub    $0x10,%rsp
  401148:	89 7d f8             	mov    %edi,-0x8(%rbp)
  40114b:	89 75 fc             	mov    %esi,-0x4(%rbp)
  40114e:	8b 45 f8             	mov    -0x8(%rbp),%eax
  401151:	03 45 fc             	add    -0x4(%rbp),%eax
  401154:	83 f8 00             	cmp    $0x0,%eax
  401157:	75 24                	jne    40117d <second_gate.cfi+0x3d>
  401159:	48 63 45 f8          	movslq -0x8(%rbp),%rax
  40115d:	48 8b 04 c5 50 40 40 	mov    0x404050(,%rax,8),%rax
  401164:	00 
  401165:	48 b9 50 14 40 00 00 	movabs $0x401450,%rcx
  40116c:	00 00 00 
  40116f:	48 39 c8             	cmp    %rcx,%rax
  401172:	74 02                	je     401176 <second_gate.cfi+0x36>
  401174:	0f 0b                	ud2    
  401176:	8b 7d fc             	mov    -0x4(%rbp),%edi
  401179:	ff d0                	callq  *%rax
  40117b:	eb 02                	jmp    40117f <second_gate.cfi+0x3f>
  40117d:	eb 00                	jmp    40117f <second_gate.cfi+0x3f>
  40117f:	48 83 c4 10          	add    $0x10,%rsp
  401183:	5d                   	pop    %rbp
  401184:	c3                   	retq   
  401185:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40118c:	00 00 00 
  40118f:	90                   	nop

0000000000401190 <second_gate_dup.cfi>:
  401190:	55                   	push   %rbp
  401191:	48 89 e5             	mov    %rsp,%rbp
  401194:	48 83 ec 10          	sub    $0x10,%rsp
  401198:	89 7d f8             	mov    %edi,-0x8(%rbp)
  40119b:	89 75 fc             	mov    %esi,-0x4(%rbp)
  40119e:	8b 45 f8             	mov    -0x8(%rbp),%eax
  4011a1:	03 45 fc             	add    -0x4(%rbp),%eax
  4011a4:	83 f8 00             	cmp    $0x0,%eax
  4011a7:	74 24                	je     4011cd <second_gate_dup.cfi+0x3d>
  4011a9:	48 63 45 f8          	movslq -0x8(%rbp),%rax
  4011ad:	48 8b 04 c5 50 40 40 	mov    0x404050(,%rax,8),%rax
  4011b4:	00 
  4011b5:	48 b9 50 14 40 00 00 	movabs $0x401450,%rcx
  4011bc:	00 00 00 
  4011bf:	48 39 c8             	cmp    %rcx,%rax
  4011c2:	74 02                	je     4011c6 <second_gate_dup.cfi+0x36>
  4011c4:	0f 0b                	ud2    
  4011c6:	8b 7d fc             	mov    -0x4(%rbp),%edi
  4011c9:	ff d0                	callq  *%rax
  4011cb:	eb 02                	jmp    4011cf <second_gate_dup.cfi+0x3f>
  4011cd:	eb 00                	jmp    4011cf <second_gate_dup.cfi+0x3f>
  4011cf:	48 83 c4 10          	add    $0x10,%rsp
  4011d3:	5d                   	pop    %rbp
  4011d4:	c3                   	retq   
  4011d5:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4011dc:	00 00 00 
  4011df:	90                   	nop

00000000004011e0 <target>:
  4011e0:	55                   	push   %rbp
  4011e1:	48 89 e5             	mov    %rsp,%rbp
  4011e4:	48 83 ec 10          	sub    $0x10,%rsp
  4011e8:	89 7d fc             	mov    %edi,-0x4(%rbp)
  4011eb:	48 bf 04 20 40 00 00 	movabs $0x402004,%rdi
  4011f2:	00 00 00 
  4011f5:	b0 00                	mov    $0x0,%al
  4011f7:	e8 34 fe ff ff       	callq  401030 <printf@plt>
  4011fc:	48 83 c4 10          	add    $0x10,%rsp
  401200:	5d                   	pop    %rbp
  401201:	c3                   	retq   
  401202:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  401209:	00 00 00 
  40120c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000401210 <origin_flow.cfi>:
  401210:	55                   	push   %rbp
  401211:	48 89 e5             	mov    %rsp,%rbp
  401214:	48 83 ec 10          	sub    $0x10,%rsp
  401218:	48 89 7d f0          	mov    %rdi,-0x10(%rbp)
  40121c:	89 75 fc             	mov    %esi,-0x4(%rbp)
  40121f:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
  401223:	8b 55 fc             	mov    -0x4(%rbp),%edx
  401226:	48 bf 0d 20 40 00 00 	movabs $0x40200d,%rdi
  40122d:	00 00 00 
  401230:	b0 00                	mov    $0x0,%al
  401232:	e8 f9 fd ff ff       	callq  401030 <printf@plt>
  401237:	31 c0                	xor    %eax,%eax
  401239:	48 83 c4 10          	add    $0x10,%rsp
  40123d:	5d                   	pop    %rbp
  40123e:	c3                   	retq   
  40123f:	90                   	nop

0000000000401240 <first_gate.cfi>:
  401240:	55                   	push   %rbp
  401241:	48 89 e5             	mov    %rsp,%rbp
  401244:	48 83 ec 10          	sub    $0x10,%rsp
  401248:	48 89 7d f0          	mov    %rdi,-0x10(%rbp)
  40124c:	89 75 fc             	mov    %esi,-0x4(%rbp)
  40124f:	83 7d fc ff          	cmpl   $0xffffffff,-0x4(%rbp)
  401253:	75 09                	jne    40125e <first_gate.cfi+0x1e>
  401255:	c7 45 f8 ff ff ff ff 	movl   $0xffffffff,-0x8(%rbp)
  40125c:	eb 78                	jmp    4012d6 <first_gate.cfi+0x96>
  40125e:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
  401262:	75 33                	jne    401297 <first_gate.cfi+0x57>
  401264:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  401268:	48 b9 30 14 40 00 00 	movabs $0x401430,%rcx
  40126f:	00 00 00 
  401272:	48 89 c2             	mov    %rax,%rdx
  401275:	48 29 ca             	sub    %rcx,%rdx
  401278:	48 89 d1             	mov    %rdx,%rcx
  40127b:	48 c1 e9 03          	shr    $0x3,%rcx
  40127f:	48 c1 e2 3d          	shl    $0x3d,%rdx
  401283:	48 09 d1             	or     %rdx,%rcx
  401286:	48 83 f9 01          	cmp    $0x1,%rcx
  40128a:	76 02                	jbe    40128e <first_gate.cfi+0x4e>
  40128c:	0f 0b                	ud2    
  40128e:	8b 7d fc             	mov    -0x4(%rbp),%edi
  401291:	31 f6                	xor    %esi,%esi
  401293:	ff d0                	callq  *%rax
  401295:	eb 38                	jmp    4012cf <first_gate.cfi+0x8f>
  401297:	48 8b 04 25 60 20 40 	mov    0x402060,%rax
  40129e:	00 
  40129f:	48 b9 30 14 40 00 00 	movabs $0x401430,%rcx
  4012a6:	00 00 00 
  4012a9:	48 89 c2             	mov    %rax,%rdx
  4012ac:	48 29 ca             	sub    %rcx,%rdx
  4012af:	48 89 d1             	mov    %rdx,%rcx
  4012b2:	48 c1 e9 03          	shr    $0x3,%rcx
  4012b6:	48 c1 e2 3d          	shl    $0x3d,%rdx
  4012ba:	48 09 d1             	or     %rdx,%rcx
  4012bd:	48 83 f9 01          	cmp    $0x1,%rcx
  4012c1:	76 02                	jbe    4012c5 <first_gate.cfi+0x85>
  4012c3:	0f 0b                	ud2    
  4012c5:	8b 7d fc             	mov    -0x4(%rbp),%edi
  4012c8:	be ff ff ff ff       	mov    $0xffffffff,%esi
  4012cd:	ff d0                	callq  *%rax
  4012cf:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
  4012d6:	8b 45 f8             	mov    -0x8(%rbp),%eax
  4012d9:	48 83 c4 10          	add    $0x10,%rsp
  4012dd:	5d                   	pop    %rbp
  4012de:	c3                   	retq   
  4012df:	90                   	nop

00000000004012e0 <third_gate.cfi>:
  4012e0:	55                   	push   %rbp
  4012e1:	48 89 e5             	mov    %rsp,%rbp
  4012e4:	48 83 ec 10          	sub    $0x10,%rsp
  4012e8:	89 7d fc             	mov    %edi,-0x4(%rbp)
  4012eb:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
  4012ef:	75 0a                	jne    4012fb <third_gate.cfi+0x1b>
  4012f1:	8b 7d fc             	mov    -0x4(%rbp),%edi
  4012f4:	e8 e7 fe ff ff       	callq  4011e0 <target>
  4012f9:	eb 02                	jmp    4012fd <third_gate.cfi+0x1d>
  4012fb:	eb 00                	jmp    4012fd <third_gate.cfi+0x1d>
  4012fd:	48 83 c4 10          	add    $0x10,%rsp
  401301:	5d                   	pop    %rbp
  401302:	c3                   	retq   
  401303:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40130a:	00 00 00 
  40130d:	0f 1f 00             	nopl   (%rax)

0000000000401310 <vuln>:
  401310:	55                   	push   %rbp
  401311:	48 89 e5             	mov    %rsp,%rbp
  401314:	48 83 ec 20          	sub    $0x20,%rsp
  401318:	48 b8 40 14 40 00 00 	movabs $0x401440,%rax
  40131f:	00 00 00 
  401322:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
  401326:	48 bf 33 20 40 00 00 	movabs $0x402033,%rdi
  40132d:	00 00 00 
  401330:	48 be 48 14 40 00 00 	movabs $0x401448,%rsi
  401337:	00 00 00 
  40133a:	48 ba 30 14 40 00 00 	movabs $0x401430,%rdx
  401341:	00 00 00 
  401344:	b0 00                	mov    $0x0,%al
  401346:	e8 e5 fc ff ff       	callq  401030 <printf@plt>
  40134b:	48 bf 58 20 40 00 00 	movabs $0x402058,%rdi
  401352:	00 00 00 
  401355:	48 8d 75 e8          	lea    -0x18(%rbp),%rsi
  401359:	b0 00                	mov    $0x0,%al
  40135b:	e8 e0 fc ff ff       	callq  401040 <__isoc99_scanf@plt>
  401360:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
  401367:	00 
  401368:	48 bf 58 20 40 00 00 	movabs $0x402058,%rdi
  40136f:	00 00 00 
  401372:	48 8d 75 f0          	lea    -0x10(%rbp),%rsi
  401376:	b0 00                	mov    $0x0,%al
  401378:	e8 c3 fc ff ff       	callq  401040 <__isoc99_scanf@plt>
  40137d:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  401384:	48 bf 5b 20 40 00 00 	movabs $0x40205b,%rdi
  40138b:	00 00 00 
  40138e:	48 8d 75 fc          	lea    -0x4(%rbp),%rsi
  401392:	b0 00                	mov    $0x0,%al
  401394:	e8 a7 fc ff ff       	callq  401040 <__isoc99_scanf@plt>
  401399:	48 8b 4d e8          	mov    -0x18(%rbp),%rcx
  40139d:	48 b8 40 14 40 00 00 	movabs $0x401440,%rax
  4013a4:	00 00 00 
  4013a7:	48 89 ca             	mov    %rcx,%rdx
  4013aa:	48 29 c2             	sub    %rax,%rdx
  4013ad:	48 89 d0             	mov    %rdx,%rax
  4013b0:	48 c1 e8 03          	shr    $0x3,%rax
  4013b4:	48 c1 e2 3d          	shl    $0x3d,%rdx
  4013b8:	48 09 d0             	or     %rdx,%rax
  4013bb:	48 83 f8 01          	cmp    $0x1,%rax
  4013bf:	76 02                	jbe    4013c3 <vuln+0xb3>
  4013c1:	0f 0b                	ud2    
  4013c3:	48 8b 7d f0          	mov    -0x10(%rbp),%rdi
  4013c7:	8b 75 fc             	mov    -0x4(%rbp),%esi
  4013ca:	ff d1                	callq  *%rcx
  4013cc:	48 83 c4 20          	add    $0x20,%rsp
  4013d0:	5d                   	pop    %rbp
  4013d1:	c3                   	retq   
  4013d2:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4013d9:	00 00 00 
  4013dc:	0f 1f 40 00          	nopl   0x0(%rax)

00000000004013e0 <init_table_on_runtime>:
  4013e0:	55                   	push   %rbp
  4013e1:	48 89 e5             	mov    %rsp,%rbp
  4013e4:	48 b8 50 14 40 00 00 	movabs $0x401450,%rax
  4013eb:	00 00 00 
  4013ee:	48 89 04 25 50 40 40 	mov    %rax,0x404050
  4013f5:	00 
  4013f6:	5d                   	pop    %rbp
  4013f7:	c3                   	retq   
  4013f8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  4013ff:	00 

0000000000401400 <main>:
  401400:	55                   	push   %rbp
  401401:	48 89 e5             	mov    %rsp,%rbp
  401404:	48 83 ec 10          	sub    $0x10,%rsp
  401408:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  40140f:	e8 cc ff ff ff       	callq  4013e0 <init_table_on_runtime>
  401414:	31 ff                	xor    %edi,%edi
  401416:	31 f6                	xor    %esi,%esi
  401418:	e8 73 fd ff ff       	callq  401190 <second_gate_dup.cfi>
  40141d:	e8 ee fe ff ff       	callq  401310 <vuln>
  401422:	31 c0                	xor    %eax,%eax
  401424:	48 83 c4 10          	add    $0x10,%rsp
  401428:	5d                   	pop    %rbp
  401429:	c3                   	retq   
  40142a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000401430 <__typeid__ZTSFviiE_global_addr>:
  401430:	e9 0b fd ff ff       	jmpq   401140 <second_gate.cfi>
  401435:	cc                   	int3   
  401436:	cc                   	int3   
  401437:	cc                   	int3   

0000000000401438 <second_gate_dup>:
  401438:	e9 53 fd ff ff       	jmpq   401190 <second_gate_dup.cfi>
  40143d:	cc                   	int3   
  40143e:	cc                   	int3   
  40143f:	cc                   	int3   

0000000000401440 <__typeid__ZTSFiPFviiEiE_global_addr>:
  401440:	e9 cb fd ff ff       	jmpq   401210 <origin_flow.cfi>
  401445:	cc                   	int3   
  401446:	cc                   	int3   
  401447:	cc                   	int3   

0000000000401448 <first_gate>:
  401448:	e9 f3 fd ff ff       	jmpq   401240 <first_gate.cfi>
  40144d:	cc                   	int3   
  40144e:	cc                   	int3   
  40144f:	cc                   	int3   

0000000000401450 <__typeid__ZTSFviE_global_addr>:
  401450:	e9 8b fe ff ff       	jmpq   4012e0 <third_gate.cfi>
  401455:	cc                   	int3   
  401456:	cc                   	int3   
  401457:	cc                   	int3   
  401458:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  40145f:	00 

0000000000401460 <__libc_csu_init>:
  401460:	f3 0f 1e fa          	endbr64 
  401464:	41 57                	push   %r15
  401466:	4c 8d 3d a3 29 00 00 	lea    0x29a3(%rip),%r15        # 403e10 <__frame_dummy_init_array_entry>
  40146d:	41 56                	push   %r14
  40146f:	49 89 d6             	mov    %rdx,%r14
  401472:	41 55                	push   %r13
  401474:	49 89 f5             	mov    %rsi,%r13
  401477:	41 54                	push   %r12
  401479:	41 89 fc             	mov    %edi,%r12d
  40147c:	55                   	push   %rbp
  40147d:	48 8d 2d 94 29 00 00 	lea    0x2994(%rip),%rbp        # 403e18 <__do_global_dtors_aux_fini_array_entry>
  401484:	53                   	push   %rbx
  401485:	4c 29 fd             	sub    %r15,%rbp
  401488:	48 83 ec 08          	sub    $0x8,%rsp
  40148c:	e8 6f fb ff ff       	callq  401000 <_init>
  401491:	48 c1 fd 03          	sar    $0x3,%rbp
  401495:	74 1f                	je     4014b6 <__libc_csu_init+0x56>
  401497:	31 db                	xor    %ebx,%ebx
  401499:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  4014a0:	4c 89 f2             	mov    %r14,%rdx
  4014a3:	4c 89 ee             	mov    %r13,%rsi
  4014a6:	44 89 e7             	mov    %r12d,%edi
  4014a9:	41 ff 14 df          	callq  *(%r15,%rbx,8)
  4014ad:	48 83 c3 01          	add    $0x1,%rbx
  4014b1:	48 39 dd             	cmp    %rbx,%rbp
  4014b4:	75 ea                	jne    4014a0 <__libc_csu_init+0x40>
  4014b6:	48 83 c4 08          	add    $0x8,%rsp
  4014ba:	5b                   	pop    %rbx
  4014bb:	5d                   	pop    %rbp
  4014bc:	41 5c                	pop    %r12
  4014be:	41 5d                	pop    %r13
  4014c0:	41 5e                	pop    %r14
  4014c2:	41 5f                	pop    %r15
  4014c4:	c3                   	retq   
  4014c5:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
  4014cc:	00 00 00 00 

00000000004014d0 <__libc_csu_fini>:
  4014d0:	f3 0f 1e fa          	endbr64 
  4014d4:	c3                   	retq   

Disassembly of section .fini:

00000000004014d8 <_fini>:
  4014d8:	f3 0f 1e fa          	endbr64 
  4014dc:	48 83 ec 08          	sub    $0x8,%rsp
  4014e0:	48 83 c4 08          	add    $0x8,%rsp
  4014e4:	c3                   	retq   
