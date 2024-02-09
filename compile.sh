mv Makefile Makefile.1
sed $'s/^    */\t/' < Makefile.1 > Makefile
make