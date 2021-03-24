import cpp


from MacroInvocation mi,Expr e
where mi.getMacroName().regexpMatch("ntoh(s|l|ll)") and 
    mi.getExpr() = e
select e,"test"
