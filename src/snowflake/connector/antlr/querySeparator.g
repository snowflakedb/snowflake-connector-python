grammar querySeparator;

@lexer::members {
def any_prefix(self, strlist):
        for to_match in strlist:
            matched = True
            for i in range(len(to_match)):
                if self._input.LA(i + 1) != ord(to_match[i]):
                    matched = False
                    break
            if matched:
                return matched
        return False


}
// Method for hacky look ahead for createFuncProc pattern detection
@parser::members {
    import re
    self.createFuncProcMatch = re.compile(
        r'CREATE(\w|\s)*(PROCEDURE|FUNCTION)')

def isCreateFuncProc(self):
        tok_list = self.ahead("CREATE")
        if len(tok_list) < 2:
            return False

        input_str = ' '.join(tok_list)
        result = self.createFuncProcMatch.match(input_str)
        if result is None:
            #print("not match CREATEFUNC:" + input_str)
            return False

        #print("got CREATEFUNC:" + input_str)
        return True

def ahead(self, begin_tok):
        MAX_SQL_LEN = 1024 * 1024 * 1024
        look_ahead = []

        next = self._input.LT(1)
        if next.text.upper() != begin_tok:
           return []
        i = 0
        while i < MAX_SQL_LEN:
            i += 1
            next = self._input.LT(i)
            if (not next is None) and (next.type == Token.EOF):
                break
            look_ahead.append(next.text.upper())

        return look_ahead
}

// To support case insensitive keywords
fragment A_ :'a' | 'A';
fragment B_ :'b' | 'B';
fragment C_ :'c' | 'C';
fragment D_ :'d' | 'D';
fragment E_ :'e' | 'E';
fragment F_ :'f' | 'F';
fragment G_ :'g' | 'G';
fragment H_ :'h' | 'H';
fragment I_ :'i' | 'I';
fragment J_ :'j' | 'J';
fragment K_ :'k' | 'K';
fragment L_ :'l' | 'L';
fragment M_ :'m' | 'M';
fragment N_ :'n' | 'N';
fragment O_ :'o' | 'O';
fragment P_ :'p' | 'P';
fragment Q_ :'q' | 'Q';
fragment R_ :'r' | 'R';
fragment S_ :'s' | 'S';
fragment T_ :'t' | 'T';
fragment U_ :'u' | 'U';
fragment V_ :'v' | 'V';
fragment W_ :'w' | 'W';
fragment X_ :'x' | 'X';
fragment Y_ :'y' | 'Y';
fragment Z_ :'z' | 'Z';


// Separators
DOT             : '.'  ; // generated as a part of Number rule
DOUBLE_COLON    : '::' ;
DOUBLE_LT       : '<<' ;
DOUBLE_GT       : '>>' ;
COLON           : ':'  ;
COMMA           : ','  ;
CLI_DELIMITER   : ';'  '>'?; // ';>' is special delimiter for Snowsql to recognize the statement requires Async run.

// Bracketing of arrays, list, expressions
LPAREN    : '(' ;
RPAREN    : ')' ;
LSQUARE   : '[' ;
RSQUARE   : ']' ;
LCURLY    : '{' ;
RCURLY    : '}' ;

// Operators
AMPERSAND            : '&';
BITWISEOR            : '|';
BITWISEXOR           : '^';
EQUAL                : '='  | '==';
COLONEQUAL           : ':=' ;
NOTEQUAL             : '<>' | '!=';
LESSTHANOREQUALTO    : '<=' ;
LESSTHAN             : '<'  ;
GREATERTHANOREQUALTO : '>=' ;
GREATERTHAN          : '>'  ;
ARROW                : '->' ;
CONCATENATION        : '||' ;
DOUBLE_ARROW         : '=>' ;
DIVIDE               : '/'  ;
PLUS                 : '+'  ;
MINUS                : '-'  ;
STAR                 : '*'  ;
MOD                  : '%'  ;

DOLLAR     : '$';
TILDE      : '~';
QUESTION   : '?';
UNDERSCORE : '_';

WS :
    (' '|'\r'|'\t'|'\n'|'\u000C') -> channel(HIDDEN)
    ;

KW_BEGIN : B_ E_ G_ I_ N_ ;
KW_END : E_ N_ D_ ;
KW_CREATE : C_ R_ E_ A_ T_ E_ ;
KW_DECLARE : D_ E_ C_ L_ A_ R_ E_;
KW_AS : A_ S_ ;
KW_FUNCTION : F_ U_ N_ C_ T_ I_ O_ N_ ;
KW_PROCEDURE : P_ R_ O_ C_ E_ D_ U_ R_ E_;
KW_OR : O_ R_ ;
KW_REPLACE : R_ E_ P_ L_ A_ C_ E_ ;
KW_TEMP : T_ E_ M_ P_ ;
KW_TEMPORARY : T_ E_ M_ P_ O_ R_ A_ R_ Y_ ;
KW_VOLATILE : V_ O_ L_ A_ T_ I_ L_ E_ ;
KW_SECURE : S_ E_ C_ U_ R_ E_ ;
KW_EXTERNAL : E_ X_ T_ E_ R_ N_ A_ L_ ;
KW_CASE : C_ A_ S_ E_ ;
KW_TRANSACTION : T_ R_ A_ N_ S_ A_ C_ T_ I_ O_ N_ ;
KW_WORK : W_ O_ R_ K_ ;
KW_NAME : N_ A_ M_ E_ ;

//when we expect a block
allKeywordsExceptEnd :
    KW_BEGIN | KW_CREATE | KW_DECLARE | KW_AS | KW_FUNCTION | KW_PROCEDURE
    | KW_OR | KW_REPLACE | KW_TEMP | KW_TEMPORARY | KW_VOLATILE | KW_SECURE
    | KW_EXTERNAL | KW_TRANSACTION | KW_NAME | KW_WORK
    ;

// LITERALS
fragment Letter
    : 'a'..'z' | 'A'..'Z'
    ;

fragment Digit
    : '0'..'9'
    ;

//----------------------------------------------------------------------------
// String specification

// A simple string is a single quoted series of character.
// Supports Unix-like escaping for control character, e.g \n, \t...
// but also Unicode specification (\uXXXX).
// To include a ' in the string, use either '' (standard SQL) or \' (SQL extensions)
fragment StringLiteralSimple:
      '\'' ( '\'\'' | '\\' . | ~( '\\' | '\'' ) )* '\'';

// Here-strings are $$ ... $$
fragment StringLiteralHere:
      '$$' ( '$' ~'$' | ~'$' )* '$$'
    ;

StringLiteral :
    StringLiteralSimple
  | StringLiteralHere
  ;

allOperators :
    AMPERSAND
    | BITWISEOR | BITWISEXOR
    | EQUAL | COLONEQUAL | NOTEQUAL | LESSTHANOREQUALTO
    | LESSTHAN | GREATERTHANOREQUALTO | GREATERTHAN
    | ARROW | CONCATENATION  | DOUBLE_ARROW
    | DIVIDE | PLUS | MINUS | STAR | MOD
    ;

allSymbols : // no semicolon
    DOT | DOUBLE_COLON | DOUBLE_LT  | DOUBLE_GT | COLON | COMMA
    | LPAREN | RPAREN | LSQUARE | RSQUARE | LCURLY | RCURLY
    | DOLLAR | UNDERSCORE | TILDE | QUESTION | '!' | '\\' | '@'
    ;

//----------------------------------------------------------------------------
// Support 3 variations on comments
// double slash or double dash comment until the end of line
//   (final newline is optional... ok if no newline at EOF)
//
// /* comment... */ ignore everything between /* and */

COMMENT:
   ( '--' ~('\n'|'\r')* '\r'? '\n'?
   | '//' ~('\n'|'\r')* '\r'? '\n'?
   | '/*' ( . )*? '*/'
   ) -> channel(9)
   ;

// Define URLPath To distinct from comment, since there could be // and /* in URLPath
URLPath:
    {self.any_prefix(["sfc://", "file://", "s3://", "S3://"])}? NonWhiteSpace+
    ;

// Use NonSeparator so comment is not part of a "GeneralWord"
GeneralWord :
    NonSeparator+
    ;

NonSeparator :
    ~(';' | ' '|'\r'|'\t'|'\n'|'\u000C' | '{' | '}' | '[' | ']' | '(' | ')' | '/' | '-')
    ;

NonWhiteSpace //non ';' and white space chars (that form a keyword, identifier, name, etc)
    : ~(';' | ' '|'\r'|'\t'|'\n'|'\u000C' )
    ;

SpecialCommand :
    '!' Letter+ ~('\n'|'\r')* '\r'? '\n'?
    ;

// chars not separated by whitespace or ';'
word :
    (UNDERSCORE | allOperators | allSymbols | GeneralWord | URLPath)+
    ;

// entry point of sql statement splitting

queriesText
    : statement* EOF
    ;

statement :
    CLI_DELIMITER*
    ({self.isCreateFuncProc()}? createFunctionStatement // create function/proc as begin...end
    | transactionStatement // not seeking begin trans.. commit/end
    | anonymousBlock  // (declare..)? begin...end
    | SpecialCommand
    | normalStatements //other than create func / begin / end
    ) CLI_DELIMITER*
    ;

anonymousBlock :
    (KW_DECLARE (noKeywordStatement CLI_DELIMITER*)+)? beginEndBlock
    ;

transactionStatement :
    KW_BEGIN (KW_WORK | KW_TRANSACTION)? (KW_NAME word)?
    ;

normalStatements :
    CLI_DELIMITER* statementBody CLI_DELIMITER*
    ;

caseExpr : KW_CASE statementBody KW_END
    ;

statementBody :
    (allKeywordsExceptEnd | word | StringLiteral | caseExpr)+
    ;

noKeywordStatement :
    (word | StringLiteral)+
    ;

createFunctionStatement :
    KW_CREATE orReplace? (temporary | KW_SECURE | KW_EXTERNAL | word)* funcOrProc
    word* KW_AS
    funcOrProcBody
    CLI_DELIMITER*
    ;

orReplace :
      KW_OR KW_REPLACE
    ;

temporary :
      ( KW_TEMP | KW_TEMPORARY | KW_VOLATILE )
    ;

funcOrProc :
    KW_FUNCTION | KW_PROCEDURE
    ;

funcOrProcBody :
    StringLiteral
    | anonymousBlock
    ;

beginEndBlock : KW_BEGIN statementInBlock* KW_END word? ;

//do not consider createFuncProc in block
statementInBlock :
    statement+
    ;
