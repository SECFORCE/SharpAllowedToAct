# SharpAllowedToAct

## Fork of SharpAllowedToAct with the following improvments:

- Allows the usage of an existing computer
- Allows to specify credentials
- Shows previous SDLL value and allows to set the security descriptor to a specific value

## Description ##

A C# implementation of a computer object takeover through Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity) based on the [research](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html) by [@elad_shamir](https://twitter.com/elad_shamir).
Credits also to [@harmj0y](https://twitter.com/harmj0y) for his [blog post](http://www.harmj0y.net/blog/activedirectory/a-case-study-in-wagging-the-dog-computer-takeover/) and to [@kevin_robertson](https://twitter.com/kevin_robertson) as I relied on the code for his [Powermad](https://github.com/Kevin-Robertson/Powermad) tool.

## Compile Instructions ## 
Make sure that the necessary NuGet packages are installed successfully and simply build the project.

## Usage

~~~
Usage: SharpAllowedToAct.exe --ComputerAccountName FAKECOMPUTER --ComputerPassword Welcome123! --TargetComputer VICTIM

Options:
-m, --ComputerAccountName
        Set the name of the new machine.
-p, --ComputerPassword
        Set the password for the new machine.
-t, --TargetComputer
        Set the name of the target computer you want to exploit. Need to have write access to the computer object.
-a, --DomainController
        Set the domain controller to use.
-d, --Domain
        Set the target domain.
-c, --Cleanup
        Empty the value of msds-allowedtoactonbehalfofotheridentity for a given computer account (Usage: '--Cleanup true'). Must be combined with --TargetComputer.
-u, --Username
        User with write access at target computer
-s, --SecDescriptor
        Value to update msds-allowedtoactonbehalfofotheridentity for a given computer account (Usage: '--Cleanup true'). Must be combined with --TargetComputer.
-w, --Password
        Password for user with write access at target computer.
~~~

