Option Explicit

' Launch the native desktop client without opening a console window.
Dim shell, fileSystem, appFolder, python, app
Set shell = CreateObject("WScript.Shell")
Set fileSystem = CreateObject("Scripting.FileSystemObject")

appFolder = fileSystem.GetParentFolderName(WScript.ScriptFullName)
python = appFolder & "\.venv\Scripts\pythonw.exe"
app = appFolder & "\app.py"

If Not fileSystem.FileExists(python) Then
    ' Some virtual environments include only python.exe. WScript keeps it hidden.
    python = appFolder & "\.venv\Scripts\python.exe"
End If

If Not fileSystem.FileExists(python) Then
    MsgBox "SEDWTIAR's desktop runtime was not found." & vbCrLf & _
        "Expected: " & appFolder & "\.venv\Scripts\python.exe", vbCritical, "SEDWTIAR could not start"
    WScript.Quit 1
End If

shell.Run Chr(34) & python & Chr(34) & " " & Chr(34) & app & Chr(34), 0, False
