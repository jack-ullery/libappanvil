#ifndef __AA_EXCEPTIONS_H__
#define __AA_EXCEPTIONS_H__

#define AA_INVALID_INCLUDE_EX	32
	#define AA_NULL_POINTER_EX	33


#define THROW_IF_NULL(x,y)
#define THROW_PARSER_EXCEPTION(x,y)

/*	#define THROW_IF_NULL(x, y) 	\
		if (x == NULL) {	\
		CONSTRUCTEX();		\
		EXCEPTION->type = AA_NULL_POINTER_EX; \
		EXCEPTION->name = "Null pointer exception"; \
		EXCEPTION->message = "Null pointer exception"; \
		goto y; \
		}	


	#define THROW_PARSER_EXCEPTION(x, y)	\
		CONSTRUCTEX(); \
		EXCEPTION->type = ANTLR3_RECOGNITION_EXCEPTION; \
		EXCEPTION->name = "Parser exception"; \
		EXCEPTION->message = x; \
		goto y; 

*/
	 static void lexer_error_handler(pANTLR3_BASE_RECOGNIZER rec)

	 {
		/* Do nothing, the parser will pick this up for us. */
	 }
#endif

