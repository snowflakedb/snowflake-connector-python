grammar querySeparator;

//to detect URL prefixes so we could differentiate URLPath and comments in lexer
// prefixes set in lexer.prefixes to allow pre-processing.
@lexer::members {
    self.prefixes = {"URL": set(["sfc://", "file://", "s3://", "S3://"])}
    self.strpattern_idxs = {}

def any_prefix(self, prefix_type):
            if self.strpattern_idxs.get(prefix_type) is None:
                self.strpattern_idxs[prefix_type] = set()

                for prefix in self.prefixes.get(prefix_type):
                    pos = self._input.strdata.find(prefix)
                    while pos >= 0:
                        self.strpattern_idxs[prefix_type].add(pos)
                        pos = self._input.strdata.find(prefix, pos+1)

            if self._input._index in self.strpattern_idxs.get(prefix_type):
                return True
            return False


}
// Method for hacky look ahead for createFuncProc pattern detection
// There are several considerations:
// 1, is_create_func_proc() will be called many times since 'statement' here is more generic.
// 2, when is_create_func_proc is called, not all the tokens are ready. so a cached solution
//    has to be incremental
@parser::members {
    self.patterns = {}
    self.token_groups = {}
    self.last_tok_idx = 0

def token_group_by_type(self):
        lexered_tok_num = len(self._input.tokens)
        if len(self.token_groups) > 0 and self.last_tok_idx >= lexered_tok_num:
            return
        for self.last_tok_idx in range(self.last_tok_idx, lexered_tok_num):
            tok = self._input.tokens[self.last_tok_idx]
            if self.token_groups.get(tok.type) is None:
                self.token_groups[tok.type] = set()
            self.token_groups[tok.type].add(tok.tokenIndex)

def is_create_func_proc(self):
        """ looking for "create [^;] (function|procedure)" pattern
        """
        from snowflake.connector.antlr.querySeparatorLexer import querySeparatorLexer
        found: set = self.patterns.get("CREATEPROC")
        if found is None or self.last_tok_idx < (len(self._input.tokens)-1):
            self.token_group_by_type()
            self.patterns["CREATEPROC"] = set()
            found = self.search_token_seq("CREATEPROC",
                                          self._input.index,
                                          [[querySeparatorLexer.KW_CREATE],
                                           [querySeparatorLexer.KW_PROCEDURE, querySeparatorLexer.KW_FUNCTION]],
                                          [querySeparatorLexer.CLI_DELIMITER]
                                          )

        cur = self._input.index
        if cur in found:
            return True

        return False

def search_token_seq(self, search_name,
                         search_start,
                         search_seq,
                         terminators):
        """
        search a token pattern by using search_seq and terminators list.
        -- search_seq is an list of list for token type. the search is to
         find all tokens matching these types in order,
         [[KW_CREATE], [KW_PROC,kW_FUNC]] means any token sequence that are
         "KW_CREATE... KW_PROC" _OR_  "KW_CREATE... KW_FUNC" will be a match
        -- terminators: the search will stop any time when hit a token type
         in terminators
        we expect no nested pattern e.g. KW_CREATE..KW_CREATE..KW_PROC..KW_PROC
        """
        search_result = set()
        self.patterns[search_name] = search_result
        search_tok_sets = [set(itr) for itr in search_seq]
        search_terminator_set = set(terminators)
        search_idx = 0
        tok_idx = search_start

        while search_idx < len(search_tok_sets) and tok_idx < len(self._input.tokens)-1:
            if self._input.tokens[tok_idx] in search_terminator_set:
                search_idx = 0
                tok_idx += 1
                continue

            if self._input.tokens[tok_idx].type in search_tok_sets[search_idx]:

                if search_idx == 0:  # mark the start position of matching pattern
                    start_pos = tok_idx
                search_idx += 1
            tok_idx += 1

            if search_idx == len(search_seq):
                search_result.add(start_pos)

        return search_result
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
    {self.any_prefix("URL")}? NonWhiteSpace+
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

// boringWord are chars not separated by whitespace or ';' in which we are not interested
// for our limited purpose(top level statement split).
boringWord :
    (UNDERSCORE | allOperators | allSymbols | GeneralWord | URLPath)+
    ;

// entry point of sql statement splitting

queriesText
    : statement* EOF
    ;

statement :
    CLI_DELIMITER*
    ({self.is_create_func_proc()}? createFunctionStatement // create function/proc as begin...end
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
    KW_BEGIN (KW_WORK | KW_TRANSACTION)? (KW_NAME boringWord)?
    ;

normalStatements :
    CLI_DELIMITER* statementBody CLI_DELIMITER*
    ;

caseExpr : KW_CASE statementBody KW_END
    ;

statementBody :
    (allKeywordsExceptEnd | boringWord | StringLiteral | caseExpr)+
    ;

noKeywordStatement :
    (boringWord | StringLiteral)+
    ;

createFunctionStatement :
    KW_CREATE orReplace? (temporary | KW_SECURE | KW_EXTERNAL | boringWord)* funcOrProc
    boringWord* KW_AS
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

beginEndBlock : KW_BEGIN statementInBlock* KW_END boringWord? ;

//do not consider createFuncProc in block
statementInBlock :
    statement+
    ;
