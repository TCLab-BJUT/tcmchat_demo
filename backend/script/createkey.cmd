# this cmdlist is for tcm_emulator create key operation 

in:  apcreate -it 04 -pwd sss
out: 1:$smkHandle

in: createwrapkey -ikh 40000000 -ish $smkHandle -is sm2 -kf $1 -pwdk $2

in: apterminate -ih $smkHandle

