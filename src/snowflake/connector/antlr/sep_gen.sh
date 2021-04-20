!/usr/bin/bash
CURRENT_PATH=$(pwd)
wget https://www.antlr.org/download/antlr-4.9.2-complete.jar
MYCLASSPATH=$CURRENT_PATH/antlr-4.9.2-complete.jar:$CLASSPATH
ANTLR4CMD="java -Xmx500M -cp $MYCLASSPATH org.antlr.v4.Tool"
$ANTLR4CMD -Dlanguage=Python3 querySeparator.g
