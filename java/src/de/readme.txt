+-------------------------------------------------------------------+
¦ YAHCT - Yet Another Hash Cash Tool - 1.01 - by Sebastian Gesemann |
+-------------------------------------------------------------------+
contact: <sgeseman \at upb \dot de>


YAHCT is a free Java implementation (including source code) released
under the terms of the GNU General Public License (Version 2). It's
capable of computing and verifying HashCash tokens of the form

	0:YYMMDD:<challange>:<computed-suffix>

The value of one token is derived from the amount of leading zeros
of its SHA1 hash. Producing tokens with higher value takes more
processing power because the probability of finding a token of value
b using a random trial is roughly 2^{-b}. (Remember Bernulli ?)
The average amount of trials until finding a token of the desired
value is therefore 2^b. (Assuming SHA-1 to have similar properties
as the random oracle hash model)

(See http://www.hashcash.org/ for more details / purpose of HashCash)

YAHCT is for now a command line program which makes use of its own
HashCash library and should run under every JRE (Java Runtime
Environment). Usage:

Type:
	java -jar /path/to/yahct.jar <yahct-arguments...>

(start YAHCT without parameters so see a listing of available
options and how to specify the challange / desired minimum value)

Examples:
	java -jar yahct.jar test 30
	java -jar yahct.jar -t 2 test 30
	java -jar yahct.jar 0:031216:test:ui0QIquZVuv check

(The 2nd example makes use of 2 threads which runs nearly twice
as fast on dual-CPU systems)
