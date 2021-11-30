# (rev) Upgrades

### Proof of Concept

For this challenge you were given a PowerPoint presentation with macros. There are some encrypted values stored in the macro that need to be decoded resulting in the flag.

### Vulnerability Explanation

Instead of extracting the macros from the PowerPoint manually (they are password protected and it's annoying to undo that), I used [Oletools](https://github.com/decalage2/oletools) to extract them for me.

```bash
[~/upgrades]$ olevba Upgrades.pptm                                                    *[master]
olevba 0.60.1.dev3 on Python 3.9.7 - http://decalage.info/python/oletools
===============================================================================
FILE: Upgrades.pptm
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO Module1.bas
in file: ppt/vbaProject.bin - OLE stream: 'VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Private Function q(g) As String
q = ""
For Each I In g
q = q & Chr((I * 59 - 54) And 255)
Next I
End Function
Sub OnSlideShowPageChange()
j = Array(q(Array(245, 46, 46, 162, 245, 162, 254, 250, 33, 185, 33)), _
q(Array(215, 120, 237, 94, 33, 162, 241, 107, 33, 20, 81, 198, 162, 219, 159, 172, 94, 33, 172, 94)), _
q(Array(245, 46, 46, 162, 89, 159, 120, 33, 162, 254, 63, 206, 63)), _
q(Array(89, 159, 120, 33, 162, 11, 198, 237, 46, 33, 107)), _
q(Array(232, 33, 94, 94, 33, 120, 162, 254, 237, 94, 198, 33)))
g = Int((UBound(j) + 1) * Rnd)
With ActivePresentation.Slides(2).Shapes(2).TextFrame
.TextRange.Text = j(g)
End With
If StrComp(Environ$(q(Array(81, 107, 33, 120, 172, 85, 185, 33))), q(Array(154, 254, 232, 3, 171, 171, 16, 29, 111, 228, 232, 245, 111, 89, 158, 219, 24, 210, 111, 171, 172, 219, 210, 46, 197, 76, 167, 233)), vbBinaryCompare) = 0 Then
VBA.CreateObject(q(Array(215, 11, 59, 120, 237, 146, 94, 236, 11, 250, 33, 198, 198))).Run (q(Array(59, 185, 46, 236, 33, 42, 33, 162, 223, 219, 162, 107, 250, 81, 94, 46, 159, 55, 172, 162, 223, 11)))
End If
End Sub


-------------------------------------------------------------------------------
VBA MACRO Slide1.cls
in file: ppt/vbaProject.bin - OLE stream: 'VBA/Slide1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Private Sub Label1_Click()

End Sub
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |Label1_Click        |Runs when the file is opened and ActiveX     |
|          |                    |objects trigger events                       |
|Suspicious|Environ             |May read system environment variables        |
|Suspicious|Run                 |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|CreateObject        |May create an OLE object                     |
|Suspicious|Chr                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
+----------+--------------------+---------------------------------------------+
```

The result is the following VBA Script: 

```VBA
Private Function q(g) As String
	q = ""
	For Each I In g
		q = q & Chr((I * 59 - 54) And 255)
		Next I
	End Function
	Sub OnSlideShowPageChange()
		j = Array(q(Array(245, 46, 46, 162, 245, 162, 254, 250, 33, 185, 33)), _
		q(Array(215, 120, 237, 94, 33, 162, 241, 107, 33, 20, 81, 198, 162, 219, 159, 172, 94, 33, 172, 94)), _
		q(Array(245, 46, 46, 162, 89, 159, 120, 33, 162, 254, 63, 206, 63)), _
		q(Array(89, 159, 120, 33, 162, 11, 198, 237, 46, 33, 107)), _
		q(Array(232, 33, 94, 94, 33, 120, 162, 254, 237, 94, 198, 33)))
		g = Int((UBound(j) + 1) * Rnd)
		With ActivePresentation.Slides(2).Shapes(2).TextFrame
			.TextRange.Text = j(g)
		End With
		If StrComp(Environ$(q(Array(81, 107, 33, 120, 172, 85, 185, 33))), q(Array(154, 254, 232, 3, 171, 171, 16, 29, 111, 228, 232, 245, 111, 89, 158, 219, 24, 210, 111, 171, 172, 219, 210, 46, 197, 76, 167, 233)), vbBinaryCompare) = 0 Then
			VBA.CreateObject(q(Array(215, 11, 59, 120, 237, 146, 94, 236, 11, 250, 33, 198, 198))).Run (q(Array(59, 185, 46, 236, 33, 42, 33, 162, 223, 219, 162, 107, 250, 81, 94, 46, 159, 55, 172, 162, 223, 11)))
		End If
	End Sub
	
```

There are a lot of what look like encrypted values however the only important ones live in the `If StrComp(Environ$...` line. I just ripped those out and threw them into an array and used the following script to solve for the flag. 

```bash 
[~/upgrades]$ python3 solve.py                                                        
HTB{33zy_VBA_M4CR0_3nC0d1NG}
```
### Solvers/Scripts Used

```python
enc_values = [154, 254, 232, 3, 171, 171, 16, 29, 111, 228, 232, 245,
111, 89, 158, 219, 24, 210, 111, 171, 172, 219, 210, 46, 197, 76, 167, 233]

# This is the "encryption" function for the values in the array
# q & Chr((I * 59 - 54) And 255)

print("".join([chr((i * 59 - 54) & 255) for i in enc_values]))
```