; ModuleID = 'main.c'
source_filename = "main.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@un_init_func_table = dso_local global [16 x void (i32)*] zeroinitializer, align 16, !dbg !0
@.src = private unnamed_addr constant [7 x i8] c"main.c\00", align 1
@anon.471c60ac9c82dcd5d750764d54c2c213.0 = private unnamed_addr constant { i16, i16, [13 x i8] } { i16 -1, i16 0, [13 x i8] c"'void (int)'\00" }
@init_func_table = dso_local global <{ void (i32, i32)*, void (i32, i32)*, [14 x void (i32, i32)*] }> <{ void (i32, i32)* @second_gate, void (i32, i32)* @second_gate_dup, [14 x void (i32, i32)*] zeroinitializer }>, align 16, !dbg !6
@.str = private unnamed_addr constant [9 x i8] c"Target!\0A\00", align 1
@.str.1 = private unnamed_addr constant [38 x i8] c"we point the %p! and arg is %d! WOW!\0A\00", align 1
@anon.471c60ac9c82dcd5d750764d54c2c213.1 = private unnamed_addr constant { i16, i16, [18 x i8] } { i16 -1, i16 0, [18 x i8] c"'void (int, int)'\00" }
@.str.2 = private unnamed_addr constant [37 x i8] c"first gate is %p, second gate is %p\0A\00", align 1
@.str.3 = private unnamed_addr constant [3 x i8] c"%p\00", align 1
@.str.4 = private unnamed_addr constant [3 x i8] c"%d\00", align 1
@anon.471c60ac9c82dcd5d750764d54c2c213.2 = private unnamed_addr constant { i16, i16, [32 x i8] } { i16 -1, i16 0, [32 x i8] c"'int (void (*)(int, int), int)'\00" }

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @second_gate(i32 %0, i32 %1) #0 !dbg !24 !type !25 !type !26 {
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  store i32 %0, i32* %3, align 4
  call void @llvm.dbg.declare(metadata i32* %3, metadata !27, metadata !DIExpression()), !dbg !28
  store i32 %1, i32* %4, align 4
  call void @llvm.dbg.declare(metadata i32* %4, metadata !29, metadata !DIExpression()), !dbg !30
  %5 = load i32, i32* %3, align 4, !dbg !31
  %6 = load i32, i32* %4, align 4, !dbg !33
  %7 = add nsw i32 %5, %6, !dbg !34
  %8 = icmp eq i32 %7, 0, !dbg !35
  br i1 %8, label %9, label %19, !dbg !36

9:                                                ; preds = %2
  %10 = load i32, i32* %3, align 4, !dbg !37
  %11 = sext i32 %10 to i64, !dbg !38
  %12 = getelementptr inbounds [16 x void (i32)*], [16 x void (i32)*]* @un_init_func_table, i64 0, i64 %11, !dbg !38
  %13 = load void (i32)*, void (i32)** %12, align 8, !dbg !38
  %14 = bitcast void (i32)* %13 to i8*, !dbg !38, !nosanitize !4
  %15 = call i1 @llvm.type.test(i8* %14, metadata !"_ZTSFviE"), !dbg !38, !nosanitize !4
  br i1 %15, label %17, label %16, !dbg !38, !nosanitize !4

16:                                               ; preds = %9
  call void @llvm.trap() #5, !dbg !38, !nosanitize !4
  unreachable, !dbg !38, !nosanitize !4

17:                                               ; preds = %9
  %18 = load i32, i32* %4, align 4, !dbg !39
  call void %13(i32 %18), !dbg !38
  br label %20, !dbg !38

19:                                               ; preds = %2
  br label %20, !dbg !40

20:                                               ; preds = %19, %17
  ret void, !dbg !41
}

; Function Attrs: nounwind readnone speculatable willreturn
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: nounwind readnone willreturn
declare i1 @llvm.type.test(i8*, metadata) #2

; Function Attrs: cold noreturn nounwind
declare void @llvm.trap() #3

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @second_gate_dup(i32 %0, i32 %1) #0 !dbg !42 !type !25 !type !26 {
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  store i32 %0, i32* %3, align 4
  call void @llvm.dbg.declare(metadata i32* %3, metadata !43, metadata !DIExpression()), !dbg !44
  store i32 %1, i32* %4, align 4
  call void @llvm.dbg.declare(metadata i32* %4, metadata !45, metadata !DIExpression()), !dbg !46
  %5 = load i32, i32* %3, align 4, !dbg !47
  %6 = load i32, i32* %4, align 4, !dbg !49
  %7 = add nsw i32 %5, %6, !dbg !50
  %8 = icmp ne i32 %7, 0, !dbg !51
  br i1 %8, label %9, label %19, !dbg !52

9:                                                ; preds = %2
  %10 = load i32, i32* %3, align 4, !dbg !53
  %11 = sext i32 %10 to i64, !dbg !54
  %12 = getelementptr inbounds [16 x void (i32)*], [16 x void (i32)*]* @un_init_func_table, i64 0, i64 %11, !dbg !54
  %13 = load void (i32)*, void (i32)** %12, align 8, !dbg !54
  %14 = bitcast void (i32)* %13 to i8*, !dbg !54, !nosanitize !4
  %15 = call i1 @llvm.type.test(i8* %14, metadata !"_ZTSFviE"), !dbg !54, !nosanitize !4
  br i1 %15, label %17, label %16, !dbg !54, !nosanitize !4

16:                                               ; preds = %9
  call void @llvm.trap() #5, !dbg !54, !nosanitize !4
  unreachable, !dbg !54, !nosanitize !4

17:                                               ; preds = %9
  %18 = load i32, i32* %4, align 4, !dbg !55
  call void %13(i32 %18), !dbg !54
  br label %20, !dbg !54

19:                                               ; preds = %2
  br label %20, !dbg !56

20:                                               ; preds = %19, %17
  ret void, !dbg !57
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @target(i32 %0) #0 !dbg !58 !type !59 !type !60 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  call void @llvm.dbg.declare(metadata i32* %2, metadata !61, metadata !DIExpression()), !dbg !62
  %3 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([9 x i8], [9 x i8]* @.str, i64 0, i64 0)), !dbg !63
  ret void, !dbg !64
}

declare !type !65 !type !66 dso_local i32 @printf(i8*, ...) #4

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @origin_flow(void (i32, i32)* %0, i32 %1) #0 !dbg !67 !type !70 !type !71 {
  %3 = alloca void (i32, i32)*, align 8
  %4 = alloca i32, align 4
  store void (i32, i32)* %0, void (i32, i32)** %3, align 8
  call void @llvm.dbg.declare(metadata void (i32, i32)** %3, metadata !72, metadata !DIExpression()), !dbg !73
  store i32 %1, i32* %4, align 4
  call void @llvm.dbg.declare(metadata i32* %4, metadata !74, metadata !DIExpression()), !dbg !75
  %5 = load void (i32, i32)*, void (i32, i32)** %3, align 8, !dbg !76
  %6 = load i32, i32* %4, align 4, !dbg !77
  %7 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([38 x i8], [38 x i8]* @.str.1, i64 0, i64 0), void (i32, i32)* %5, i32 %6), !dbg !78
  ret i32 0, !dbg !79
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @first_gate(void (i32, i32)* %0, i32 %1) #0 !dbg !80 !type !70 !type !71 {
  %3 = alloca i32, align 4
  %4 = alloca void (i32, i32)*, align 8
  %5 = alloca i32, align 4
  store void (i32, i32)* %0, void (i32, i32)** %4, align 8
  call void @llvm.dbg.declare(metadata void (i32, i32)** %4, metadata !81, metadata !DIExpression()), !dbg !82
  store i32 %1, i32* %5, align 4
  call void @llvm.dbg.declare(metadata i32* %5, metadata !83, metadata !DIExpression()), !dbg !84
  %6 = load i32, i32* %5, align 4, !dbg !85
  %7 = icmp eq i32 %6, -1, !dbg !87
  br i1 %7, label %8, label %9, !dbg !88

8:                                                ; preds = %2
  store i32 -1, i32* %3, align 4, !dbg !89
  br label %27, !dbg !89

9:                                                ; preds = %2
  %10 = load i32, i32* %5, align 4, !dbg !90
  %11 = icmp eq i32 %10, 0, !dbg !92
  br i1 %11, label %12, label %19, !dbg !93

12:                                               ; preds = %9
  %13 = load void (i32, i32)*, void (i32, i32)** %4, align 8, !dbg !94
  %14 = bitcast void (i32, i32)* %13 to i8*, !dbg !94, !nosanitize !4
  %15 = call i1 @llvm.type.test(i8* %14, metadata !"_ZTSFviiE"), !dbg !94, !nosanitize !4
  br i1 %15, label %17, label %16, !dbg !94, !nosanitize !4

16:                                               ; preds = %12
  call void @llvm.trap() #5, !dbg !94, !nosanitize !4
  unreachable, !dbg !94, !nosanitize !4

17:                                               ; preds = %12
  %18 = load i32, i32* %5, align 4, !dbg !95
  call void %13(i32 %18, i32 0), !dbg !94
  br label %26, !dbg !94

19:                                               ; preds = %9
  %20 = load void (i32, i32)*, void (i32, i32)** getelementptr inbounds ([16 x void (i32, i32)*], [16 x void (i32, i32)*]* bitcast (<{ void (i32, i32)*, void (i32, i32)*, [14 x void (i32, i32)*] }>* @init_func_table to [16 x void (i32, i32)*]*), i64 0, i64 0), align 16, !dbg !96
  %21 = bitcast void (i32, i32)* %20 to i8*, !dbg !96, !nosanitize !4
  %22 = call i1 @llvm.type.test(i8* %21, metadata !"_ZTSFviiE"), !dbg !96, !nosanitize !4
  br i1 %22, label %24, label %23, !dbg !96, !nosanitize !4

23:                                               ; preds = %19
  call void @llvm.trap() #5, !dbg !96, !nosanitize !4
  unreachable, !dbg !96, !nosanitize !4

24:                                               ; preds = %19
  %25 = load i32, i32* %5, align 4, !dbg !97
  call void %20(i32 %25, i32 -1), !dbg !96
  br label %26

26:                                               ; preds = %24, %17
  store i32 0, i32* %3, align 4, !dbg !98
  br label %27, !dbg !98

27:                                               ; preds = %26, %8
  %28 = load i32, i32* %3, align 4, !dbg !99
  ret i32 %28, !dbg !99
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @third_gate(i32 %0) #0 !dbg !100 !type !59 !type !60 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  call void @llvm.dbg.declare(metadata i32* %2, metadata !101, metadata !DIExpression()), !dbg !102
  %3 = load i32, i32* %2, align 4, !dbg !103
  %4 = icmp eq i32 %3, 0, !dbg !105
  br i1 %4, label %5, label %7, !dbg !106

5:                                                ; preds = %1
  %6 = load i32, i32* %2, align 4, !dbg !107
  call void @target(i32 %6), !dbg !108
  br label %8, !dbg !108

7:                                                ; preds = %1
  br label %8, !dbg !109

8:                                                ; preds = %7, %5
  ret void, !dbg !110
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @vuln() #0 !dbg !111 !type !114 !type !115 {
  %1 = alloca i32 (void (i32, i32)*, i32)*, align 8
  %2 = alloca void (i32, i32)*, align 8
  %3 = alloca i32, align 4
  call void @llvm.dbg.declare(metadata i32 (void (i32, i32)*, i32)** %1, metadata !116, metadata !DIExpression()), !dbg !118
  store i32 (void (i32, i32)*, i32)* @origin_flow, i32 (void (i32, i32)*, i32)** %1, align 8, !dbg !118
  %4 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([37 x i8], [37 x i8]* @.str.2, i64 0, i64 0), i32 (void (i32, i32)*, i32)* @first_gate, void (i32, i32)* @second_gate), !dbg !119
  %5 = call i32 (i8*, ...) @__isoc99_scanf(i8* getelementptr inbounds ([3 x i8], [3 x i8]* @.str.3, i64 0, i64 0), i32 (void (i32, i32)*, i32)** %1), !dbg !120
  call void @llvm.dbg.declare(metadata void (i32, i32)** %2, metadata !121, metadata !DIExpression()), !dbg !122
  store void (i32, i32)* null, void (i32, i32)** %2, align 8, !dbg !122
  %6 = call i32 (i8*, ...) @__isoc99_scanf(i8* getelementptr inbounds ([3 x i8], [3 x i8]* @.str.3, i64 0, i64 0), void (i32, i32)** %2), !dbg !123
  call void @llvm.dbg.declare(metadata i32* %3, metadata !124, metadata !DIExpression()), !dbg !125
  store i32 0, i32* %3, align 4, !dbg !125
  %7 = call i32 (i8*, ...) @__isoc99_scanf(i8* getelementptr inbounds ([3 x i8], [3 x i8]* @.str.4, i64 0, i64 0), i32* %3), !dbg !126
  %8 = load i32 (void (i32, i32)*, i32)*, i32 (void (i32, i32)*, i32)** %1, align 8, !dbg !127
  %9 = bitcast i32 (void (i32, i32)*, i32)* %8 to i8*, !dbg !127, !nosanitize !4
  %10 = call i1 @llvm.type.test(i8* %9, metadata !"_ZTSFiPFviiEiE"), !dbg !127, !nosanitize !4
  br i1 %10, label %12, label %11, !dbg !127, !nosanitize !4

11:                                               ; preds = %0
  call void @llvm.trap() #5, !dbg !127, !nosanitize !4
  unreachable, !dbg !127, !nosanitize !4

12:                                               ; preds = %0
  %13 = load void (i32, i32)*, void (i32, i32)** %2, align 8, !dbg !128
  %14 = load i32, i32* %3, align 4, !dbg !129
  %15 = call i32 %8(void (i32, i32)* %13, i32 %14), !dbg !127
  ret i32 0, !dbg !130
}

declare !type !65 !type !66 dso_local i32 @__isoc99_scanf(i8*, ...) #4

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @init_table_on_runtime() #0 !dbg !131 !type !114 !type !115 {
  store void (i32)* @third_gate, void (i32)** getelementptr inbounds ([16 x void (i32)*], [16 x void (i32)*]* @un_init_func_table, i64 0, i64 0), align 16, !dbg !132
  ret i32 0, !dbg !133
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 !dbg !134 !type !114 !type !115 {
  %1 = alloca i32, align 4
  store i32 0, i32* %1, align 4
  %2 = call i32 @init_table_on_runtime(), !dbg !135
  call void @second_gate_dup(i32 0, i32 0), !dbg !136
  %3 = call i32 @vuln(), !dbg !137
  ret i32 %3, !dbg !138
}

attributes #0 = { noinline nounwind optnone uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nounwind readnone speculatable willreturn }
attributes #2 = { nounwind readnone willreturn }
attributes #3 = { cold noreturn nounwind }
attributes #4 = { "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #5 = { noreturn nounwind }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!19, !20, !21, !22}
!llvm.ident = !{!23}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "un_init_func_table", scope: !2, file: !3, line: 4, type: !15, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "clang version 10.0.0-4ubuntu1 ", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !4, globals: !5, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "main.c", directory: "/home/kyuwoncho18/sandbox/ADOAG/examples")
!4 = !{}
!5 = !{!0, !6}
!6 = !DIGlobalVariableExpression(var: !7, expr: !DIExpression())
!7 = distinct !DIGlobalVariable(name: "init_func_table", scope: !2, file: !3, line: 20, type: !8, isLocal: false, isDefinition: true)
!8 = !DICompositeType(tag: DW_TAG_array_type, baseType: !9, size: 1024, elements: !13)
!9 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !10, size: 64)
!10 = !DISubroutineType(types: !11)
!11 = !{null, !12, !12}
!12 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!13 = !{!14}
!14 = !DISubrange(count: 16)
!15 = !DICompositeType(tag: DW_TAG_array_type, baseType: !16, size: 1024, elements: !13)
!16 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !17, size: 64)
!17 = !DISubroutineType(types: !18)
!18 = !{null, !12}
!19 = !{i32 7, !"Dwarf Version", i32 4}
!20 = !{i32 2, !"Debug Info Version", i32 3}
!21 = !{i32 1, !"wchar_size", i32 4}
!22 = !{i32 4, !"CFI Canonical Jump Tables", i32 1}
!23 = !{!"clang version 10.0.0-4ubuntu1 "}
!24 = distinct !DISubprogram(name: "second_gate", scope: !3, file: !3, line: 6, type: !10, scopeLine: 6, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !4)
!25 = !{i64 0, !"_ZTSFviiE"}
!26 = !{i64 0, !"_ZTSFviiE.generalized"}
!27 = !DILocalVariable(name: "x", arg: 1, scope: !24, file: !3, line: 6, type: !12)
!28 = !DILocation(line: 6, column: 22, scope: !24)
!29 = !DILocalVariable(name: "y", arg: 2, scope: !24, file: !3, line: 6, type: !12)
!30 = !DILocation(line: 6, column: 29, scope: !24)
!31 = !DILocation(line: 7, column: 9, scope: !32)
!32 = distinct !DILexicalBlock(scope: !24, file: !3, line: 7, column: 9)
!33 = !DILocation(line: 7, column: 13, scope: !32)
!34 = !DILocation(line: 7, column: 11, scope: !32)
!35 = !DILocation(line: 7, column: 15, scope: !32)
!36 = !DILocation(line: 7, column: 9, scope: !24)
!37 = !DILocation(line: 8, column: 28, scope: !32)
!38 = !DILocation(line: 8, column: 9, scope: !32)
!39 = !DILocation(line: 8, column: 31, scope: !32)
!40 = !DILocation(line: 10, column: 9, scope: !32)
!41 = !DILocation(line: 11, column: 1, scope: !24)
!42 = distinct !DISubprogram(name: "second_gate_dup", scope: !3, file: !3, line: 13, type: !10, scopeLine: 13, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !4)
!43 = !DILocalVariable(name: "x", arg: 1, scope: !42, file: !3, line: 13, type: !12)
!44 = !DILocation(line: 13, column: 26, scope: !42)
!45 = !DILocalVariable(name: "y", arg: 2, scope: !42, file: !3, line: 13, type: !12)
!46 = !DILocation(line: 13, column: 33, scope: !42)
!47 = !DILocation(line: 14, column: 9, scope: !48)
!48 = distinct !DILexicalBlock(scope: !42, file: !3, line: 14, column: 9)
!49 = !DILocation(line: 14, column: 13, scope: !48)
!50 = !DILocation(line: 14, column: 11, scope: !48)
!51 = !DILocation(line: 14, column: 15, scope: !48)
!52 = !DILocation(line: 14, column: 9, scope: !42)
!53 = !DILocation(line: 15, column: 28, scope: !48)
!54 = !DILocation(line: 15, column: 9, scope: !48)
!55 = !DILocation(line: 15, column: 31, scope: !48)
!56 = !DILocation(line: 17, column: 9, scope: !48)
!57 = !DILocation(line: 18, column: 1, scope: !42)
!58 = distinct !DISubprogram(name: "target", scope: !3, file: !3, line: 22, type: !17, scopeLine: 22, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !4)
!59 = !{i64 0, !"_ZTSFviE"}
!60 = !{i64 0, !"_ZTSFviE.generalized"}
!61 = !DILocalVariable(name: "x", arg: 1, scope: !58, file: !3, line: 22, type: !12)
!62 = !DILocation(line: 22, column: 17, scope: !58)
!63 = !DILocation(line: 23, column: 5, scope: !58)
!64 = !DILocation(line: 24, column: 1, scope: !58)
!65 = !{i64 0, !"_ZTSFiPKczE"}
!66 = !{i64 0, !"_ZTSFiPKvzE.generalized"}
!67 = distinct !DISubprogram(name: "origin_flow", scope: !3, file: !3, line: 26, type: !68, scopeLine: 26, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !4)
!68 = !DISubroutineType(types: !69)
!69 = !{!12, !9, !12}
!70 = !{i64 0, !"_ZTSFiPFviiEiE"}
!71 = !{i64 0, !"_ZTSFiPviE.generalized"}
!72 = !DILocalVariable(name: "arg_func", arg: 1, scope: !67, file: !3, line: 26, type: !9)
!73 = !DILocation(line: 26, column: 24, scope: !67)
!74 = !DILocalVariable(name: "num", arg: 2, scope: !67, file: !3, line: 26, type: !12)
!75 = !DILocation(line: 26, column: 49, scope: !67)
!76 = !DILocation(line: 27, column: 54, scope: !67)
!77 = !DILocation(line: 27, column: 64, scope: !67)
!78 = !DILocation(line: 27, column: 5, scope: !67)
!79 = !DILocation(line: 28, column: 5, scope: !67)
!80 = distinct !DISubprogram(name: "first_gate", scope: !3, file: !3, line: 31, type: !68, scopeLine: 31, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !4)
!81 = !DILocalVariable(name: "arg_func", arg: 1, scope: !80, file: !3, line: 31, type: !9)
!82 = !DILocation(line: 31, column: 23, scope: !80)
!83 = !DILocalVariable(name: "num", arg: 2, scope: !80, file: !3, line: 31, type: !12)
!84 = !DILocation(line: 31, column: 48, scope: !80)
!85 = !DILocation(line: 32, column: 8, scope: !86)
!86 = distinct !DILexicalBlock(scope: !80, file: !3, line: 32, column: 8)
!87 = !DILocation(line: 32, column: 12, scope: !86)
!88 = !DILocation(line: 32, column: 8, scope: !80)
!89 = !DILocation(line: 33, column: 9, scope: !86)
!90 = !DILocation(line: 34, column: 8, scope: !91)
!91 = distinct !DILexicalBlock(scope: !80, file: !3, line: 34, column: 8)
!92 = !DILocation(line: 34, column: 12, scope: !91)
!93 = !DILocation(line: 34, column: 8, scope: !80)
!94 = !DILocation(line: 35, column: 9, scope: !91)
!95 = !DILocation(line: 35, column: 18, scope: !91)
!96 = !DILocation(line: 37, column: 9, scope: !91)
!97 = !DILocation(line: 37, column: 28, scope: !91)
!98 = !DILocation(line: 38, column: 5, scope: !80)
!99 = !DILocation(line: 39, column: 1, scope: !80)
!100 = distinct !DISubprogram(name: "third_gate", scope: !3, file: !3, line: 41, type: !17, scopeLine: 41, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !4)
!101 = !DILocalVariable(name: "x", arg: 1, scope: !100, file: !3, line: 41, type: !12)
!102 = !DILocation(line: 41, column: 21, scope: !100)
!103 = !DILocation(line: 42, column: 8, scope: !104)
!104 = distinct !DILexicalBlock(scope: !100, file: !3, line: 42, column: 8)
!105 = !DILocation(line: 42, column: 10, scope: !104)
!106 = !DILocation(line: 42, column: 8, scope: !100)
!107 = !DILocation(line: 43, column: 16, scope: !104)
!108 = !DILocation(line: 43, column: 9, scope: !104)
!109 = !DILocation(line: 45, column: 9, scope: !104)
!110 = !DILocation(line: 46, column: 1, scope: !100)
!111 = distinct !DISubprogram(name: "vuln", scope: !3, file: !3, line: 48, type: !112, scopeLine: 48, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !4)
!112 = !DISubroutineType(types: !113)
!113 = !{!12}
!114 = !{i64 0, !"_ZTSFiE"}
!115 = !{i64 0, !"_ZTSFiE.generalized"}
!116 = !DILocalVariable(name: "vuln_ptr", scope: !111, file: !3, line: 50, type: !117)
!117 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !68, size: 64)
!118 = !DILocation(line: 50, column: 11, scope: !111)
!119 = !DILocation(line: 51, column: 5, scope: !111)
!120 = !DILocation(line: 52, column: 5, scope: !111)
!121 = !DILocalVariable(name: "arg_func", scope: !111, file: !3, line: 55, type: !9)
!122 = !DILocation(line: 55, column: 12, scope: !111)
!123 = !DILocation(line: 56, column: 5, scope: !111)
!124 = !DILocalVariable(name: "arg_num", scope: !111, file: !3, line: 57, type: !12)
!125 = !DILocation(line: 57, column: 9, scope: !111)
!126 = !DILocation(line: 58, column: 5, scope: !111)
!127 = !DILocation(line: 60, column: 5, scope: !111)
!128 = !DILocation(line: 60, column: 14, scope: !111)
!129 = !DILocation(line: 60, column: 24, scope: !111)
!130 = !DILocation(line: 61, column: 5, scope: !111)
!131 = distinct !DISubprogram(name: "init_table_on_runtime", scope: !3, file: !3, line: 64, type: !112, scopeLine: 64, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !4)
!132 = !DILocation(line: 65, column: 27, scope: !131)
!133 = !DILocation(line: 66, column: 5, scope: !131)
!134 = distinct !DISubprogram(name: "main", scope: !3, file: !3, line: 69, type: !112, scopeLine: 69, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !4)
!135 = !DILocation(line: 70, column: 5, scope: !134)
!136 = !DILocation(line: 71, column: 5, scope: !134)
!137 = !DILocation(line: 72, column: 12, scope: !134)
!138 = !DILocation(line: 72, column: 5, scope: !134)
