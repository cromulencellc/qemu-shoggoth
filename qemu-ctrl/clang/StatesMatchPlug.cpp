/*
 * Rapid Analysis QEMU System Emulator
 *
 * Copyright (c) 2020 Cromulence LLC
 *
 * Distribution Statement A
 *
 * Approved for Public Release, Distribution Unlimited
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 * 
 * The creation of this code was funded by the US Government.
 */

// Clang includes
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"

// LLVM includes
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

// Standard includes
#include <memory>
#include <string>
#include <vector>

// // Declares clang::SyntaxOnlyAction.
// #include "clang/Frontend/FrontendAction.h"
// #include "clang/Tooling/CommonOptionsParser.h"
// #include "clang/Tooling/Tooling.h"
// // Declares llvm::cl::extrahelp.
// #include "llvm/Support/CommandLine.h"
// #include "llvm/ADT/ArrayRef.h"
// #include "llvm/ADT/StringRef.h"
// #include "llvm/Support/raw_ostream.h"
// //ASTMatcher Support
// #include "clang/ASTMatchers/ASTMatchers.h"
// #include "clang/ASTMatchers/ASTMatchFinder.h"
// //Allows for context
// #include "clang/AST/ASTContext.h"
// #include "clang/AST/Stmt.h"

// #include "clang/AST/ASTConsumer.h"
// #include "clang/AST/ASTContext.h"
// #include "clang/AST/RecursiveASTVisitor.h"
// #include "clang/Basic/Version.h"
// #include "clang/Frontend/CompilerInstance.h"
// #include "clang/Frontend/FrontendPluginRegistry.h"
// #include "clang/Frontend/MultiplexConsumer.h"
// #include "clang/Sema/Sema.h"
// #include "llvm/ADT/DenseMap.h"

// #include "clang/AST/Decl.h"
// #include "clang/AST/Type.h"
// #include "clang/Basic/Diagnostic.h"

// #include <memory>
// #include <string>
// #include <vector>

/*
StatementMatcher StateMatcher =
  binaryOperator(hasOperatorName("="),hasLHS(memberExpr()), 
  hasRHS(anyOf(unaryOperator(hasOperatorName("&"), hasUnaryOperand(declRefExpr(
           to(varDecl(anything()))))), implicitCastExpr()))).bind("_iLoveDogs");
*/

// StatementMatcher StateMatcher =
//   binaryOperator(hasOperatorName("="),hasLHS(memberExpr(member(hasName("vmsd")))), 
//   hasRHS(anyOf(unaryOperator(hasOperatorName("&"), hasUnaryOperand(declRefExpr(
//            to(varDecl(anything()))))), implicitCastExpr()))).bind("_iLoveDogs");

// StatementMatcher StateMatcher =
//   binaryOperator(hasOperatorName("="),hasLHS(memberExpr(member(hasName("vmsd")))), 
//     hasRHS(anyOf(unaryOperator(hasOperatorName("&"), hasUnaryOperand(declRefExpr(
//       to(varDecl(anything()))))), implicitCastExpr(hasDescendant(unaryOperator(hasOperatorName("&"), 
//         hasUnaryOperand(declRefExpr(to(varDecl(anything())))))))))).bind("_iLoveDogs");

// class StateMatchPrint : public MatchFinder::MatchCallback {
// public :
//   virtual void run(const MatchFinder::MatchResult &Result) {
//     if (const BinaryOperator *FS = Result.Nodes.getNodeAs<clang::BinaryOperator>("_iLoveDogs"))
//       FS->dump();
//   }
// };

namespace ClangVariables {

/// Callback class for clang-variable matches.
class MatchHandler : public clang::ast_matchers::MatchFinder::MatchCallback {
 public:
  using MatchResult = clang::ast_matchers::MatchFinder::MatchResult;

  /// Handles the matched variable.
  ///
  /// Checks if the name of the matched variable is either empty or prefixed
  /// with `clang_` else emits a diagnostic and FixItHint.
  void run(const MatchResult& Result) {
    const clang::BinaryOperator* Variable =
        Result.Nodes.getNodeAs<clang::BinaryOperator>("clang");

        Variable->dump();
    const clang::UnaryOperator* Variable2 = 
        Result.Nodes.getNodeAs<clang::UnaryOperator>("bang");

        Variable2->dump();
    // const llvm::StringRef Name = Variable->getName();

    // if (Name.empty() || Name.startswith("clang_")) return;

    // clang::DiagnosticsEngine& Engine = Result.Context->getDiagnostics();
    // const unsigned ID =
    //     Engine.getCustomDiagID(clang::DiagnosticsEngine::Warning,
    //                            "clang variable must have 'clang_' prefix");

    // /// Hint to the user to prefix the variable with 'clang_'.
    // const clang::FixItHint FixIt =
    //     clang::FixItHint::CreateInsertion(Variable->getLocation(), "clang_");

    // Engine.Report(Variable->getLocation(), ID).AddFixItHint(FixIt);
  }
};  // namespace ClangVariables

/// Dispatches the ASTMatcher.
class Consumer : public clang::ASTConsumer {
 public:
  /// Creates the matcher for .vmsd and dispatches it on the TU.
  void HandleTranslationUnit(clang::ASTContext& Context) override {
    using namespace clang::ast_matchers;  // NOLINT(build/namespaces)

    // clang-format off
    const auto Matcher = binaryOperator(
      hasOperatorName("="),hasLHS(memberExpr(member(hasName("vmsd")))), 
      hasRHS(anyOf(unaryOperator(hasOperatorName("&"), 
        hasUnaryOperand(declRefExpr(to(varDecl(anything()))))), 
        implicitCastExpr(hasDescendant(unaryOperator(hasOperatorName("&"), 
        hasUnaryOperand(declRefExpr(to(varDecl(anything())))))))))).bind("clang");

    const auto Matcher2 = unaryOperator(hasParent(callExpr(hasDescendant(implicitCastExpr
      (hasDescendant(declRefExpr(to(varDecl()))))))), hasOperatorName("&"), 
        hasUnaryOperand(declRefExpr(to(varDecl(anything()))))).bind("bang");
    
    // const auto Matcher2 = callExpr(argumentCountIs(7),hasDescendant(implicitCastExpr
    //   (hasDescendant(declRefExpr(/*hasName("vmstate_register_with_alias_id")*/)))),
    //     hasDescendant(unaryOperator(hasOperatorName("&"), hasUnaryOperand(declRefExpr(
    //       to(varDecl(anything()))))))).bind("bang");

    // varDecl(
    //   isExpansionInMainFile(),
    //   hasType(isConstQualified()),                              // const
    //   hasInitializer(
    //     hasType(cxxRecordDecl(
    //       isLambda(),                                           // lambda
    //       has(functionTemplateDecl(                             // auto
    //         has(cxxMethodDecl(
    //           isNoThrow(),                                      // noexcept
    //           hasBody(compoundStmt(hasDescendant(gotoStmt())))  // goto
    //   )))))))).bind("clang");
    // clang-format on

    MatchHandler Handler; MatchHandler Handler2;
    MatchFinder MatchFinder;
    MatchFinder.addMatcher(Matcher, &Handler);
    MatchFinder.addMatcher(Matcher2, &Handler2);
    MatchFinder.matchAST(Context);
  }
};

/// Creates an `ASTConsumer` and logs begin and end of file processing.
class Action : public clang::ASTFrontendAction {
 public:
  using ASTConsumerPointer = std::unique_ptr<clang::ASTConsumer>;

  ASTConsumerPointer CreateASTConsumer(clang::CompilerInstance& Compiler,
                                       llvm::StringRef) override {
    //return std::make_unique<Consumer>();

    return std::unique_ptr<Consumer>(new Consumer());
  }

  // bool BeginSourceFileAction(clang::CompilerInstance& Compiler,
  //                            llvm::StringRef Filename) override {
  //   llvm::errs() << "Processing " << Filename << "\n\n";
  //   return true;
  // }

  // void EndSourceFileAction() override {
  //   llvm::errs() << "\nFinished processing file ...\n";
  // }
};
}  // namespace ClangVariables





// Apply a custom category to all command-line options so that they are the
// only ones displayed.
//static llvm::cl::OptionCategory MyToolCategory("my-tool options");

static llvm::cl::OptionCategory ToolCategory("clang-variables options");

// CommonOptionsParser declares HelpMessage with a description of the common
// command-line options related to the compilation database and input files.
// It's nice to have this help message in all tools.
static llvm::cl::extrahelp CommonHelp(clang::tooling::CommonOptionsParser::HelpMessage);

// A help message for this specific tool can be added afterwards.
llvm::cl::extrahelp MoreHelp(R"(
  Finds all .vmsd instances, including implicit casts)");

// int main(int argc, const char **argv) {
//     CommonOptionsParser OptionsParser(argc, argv, MyToolCategory);
//     ClangTool Tool(OptionsParser.getCompilations(),
//                  OptionsParser.getSourcePathList());



//     StateMatchPrint Printer;
//     MatchFinder Finder;
//     Finder.addMatcher(StateMatcher, &Printer);//     return Tool.run(newFrontendActionFactory(&Finder).get());
// }

auto main(int argc, const char* argv[]) -> int {
  using namespace clang::tooling;

  CommonOptionsParser OptionsParser(argc, argv, ToolCategory);
  ClangTool Tool(OptionsParser.getCompilations(),
                 OptionsParser.getSourcePathList());

  const auto Action = newFrontendActionFactory<ClangVariables::Action>();
  return Tool.run(Action.get());
}

