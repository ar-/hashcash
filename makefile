JFLAGS = -g
JC = javac
RFLAGS = cvfm
JR = jar
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
	com/security/cpu/hashcash/HashCash.java \
	com/security/mem/mbound/MBound.java \
	com/security/ppost/PennyPost.java \
	com/security/util/CashUtils.java

DATA = \
	fndef/functionA.dat \
	fndef/functionT.dat

EXTRA = 'com/security/ppost/PennyPost$$HashKeys.class'

default: classes

classes: $(CLASSES:.java=.class)

jar: 
	$(JR) $(RFLAGS) ppost.jar META-INF/MANIFEST.MF $(DATA) $(EXTRA) $(CLASSES:.java=.class)

clean:
	$(RM) $(CLASSES:.java=.class) $(EXTRA) ppost.jar
