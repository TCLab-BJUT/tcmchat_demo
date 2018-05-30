# this cmdlist is for tcm_emulator test 

in:  apcreate -it 04 -pwd sss
out: 1:$smkHandle

in: loadkey -ih $smkHandle -kf $1
out: 1:$keyHandle

in: apterminate -ih $smkHandle

in: apcreate -it 01 -iv $keyHandle -pwd $2
out: 1:$keyAuthHandle

in: sm2decrypt -ik $keyHandle -is $keyAuthHandle -rf switch.key  -wf session.key

in: apterminate -ih $keyAuthHandle
