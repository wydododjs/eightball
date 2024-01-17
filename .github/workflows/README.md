Compile EightBall.java and run it.  It takes an integer as an argument:

java EightBall 391
java EightBall 2000

Normally, this program replies with a message from the files 0, 1, or 2.  However,
due to bad error handling, if you specify a filename instead of an integer as
the argument, it shows the contents of the file.  (For simplicity, the
user input comes from the command-line argument.  What would happen if it
came from a web form?)  Try:

java EightBall /etc/passwd         (on Unix)
java EightBall C:\autoexec.bat     (on Windows)


Run Fortify Static Code Analyzer to scan the code:

$ sourceanalyzer -b EightBall -clean
$ sourceanalyzer -b EightBall EightBall.java
$ sourceanalyzer -b EightBall -scan -f EightBall.fpr

Open the results in Audit Workbench:

$ auditworkbench EightBall.fpr

The output should contain vulnerabilities in the following categories:

      Path Manipulation
      Unreleased Resource: Streams
      J2EE Bad Practices: Leftover Debug Code

The Fortify analysis might detect other issues depending on the Rulepack version 
used in the scan.

The Unchecked Return Value warns that FileReader.read() could have failed and
that its return value should be checked before the output is used.

The Path Manipulation vulnerability indicates that the user can control
the file opened by the FileReader. The Unreleased Resource vulnerability
indicates that the program does not close the FileReader.

The J2EE Bad Practices vulnerability indicates the presence of a main()
method, which should not appear in a J2EE application. Because this is not
a J2EE application, this category of vulnerabilities does not apply.
We can configure which categories of rules are displayed based on
the type of application using the Audit Guide in Audit Workbench.
