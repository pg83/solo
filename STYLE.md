# C++ style

This is the shared house C++ style, common to all our projects. Readability
and a stable, unsurprising shape are more important than saving vertical
space. `.clang-format` encodes the mechanical subset; the naming, organization
and constructor rules below remain part of review.

This file is identical in every project that follows it. The few settings
that differ per project — the project macro prefix, the public namespace, and
any documented deviations — live in `STYLE_PRJ.md` next to this file.

## Names

- Types, enum values and test names use `UpperCamelCase`.
- Functions, methods, variables and parameters use `lowerCamelCase`.
- Private data members use `lowerCamelCase_` with a trailing underscore.
- Compile-time constants use `lowerCamelCase` unless they are C-style ABI
  constants or macros.
- Macros use `UPPER_SNAKE_CASE` and project-owned macros use the project's
  prefix named in `STYLE_PRJ.md`. Names required by a system header or
  protocol retain their external spelling.
- Acronyms are words inside an identifier: `HttpClient`, `IoReactor`,
  `utf8Decoder`, not `HTTPClient`, `IOReactor` or `utf8_decoder`.
- Source filenames are lowercase `snake_case`. Every `.h` has a corresponding
  `.cpp`, even when that translation unit only includes the header to verify
  that the header compiles on its own. Objective-C++ headers may instead have
  a corresponding `.mm`.

Do not encode scope or type in a name. Prefer a precise noun or verb over a
prefix such as `m_`, `p_`, `str_` or `is_`.

## Braces and indentation

- Use four spaces. Tabs are forbidden.
- Indent the contents of every namespace, including an anonymous namespace,
  by one level. The namespace declaration itself remains at its enclosing
  scope.
- Opening braces are attached for namespaces, types, functions, lambdas and
  control flow. `else`, `catch` and `while` in a `do` statement stay on the
  same line as the preceding closing brace.
- Every braced body spans multiple lines. Do not write one-line functions,
  control statements, types or namespaces.
- Braces are required for every `if`, `else`, loop and `switch` arm body, even
  when the body is one statement.
- `case` labels are indented one level inside their `switch`.
- Preprocessor directives nested under a conditional are indented before the
  `#`.

```cpp
struct Example: public Interface {
    void run() override {
        if (ready) {
            consume();
        }
    }
};
```

A program's code is not wrapped in a project namespace; a library declares its
public API in the namespace named in `STYLE_PRJ.md`. Use anonymous namespaces
for translation-unit-local declarations, indent their contents, and do not add
comments to namespace-closing braces.

## Constructors

Constructors are the deliberate exception to the attached-brace rule. Put the
initializer list on separate lines, put `:` before the first initializer and a
leading comma before every following initializer, then put the body brace on
its own line:

```cpp
Widget::Widget(int width, int height)
    : width_(width)
    , height_(height)
{
}
```

Use the same shape for delegating constructors and in-class definitions. Do
not omit the empty body and do not put `{` after the last initializer.

Clang-format 21 cannot express a brace break for constructors without also
breaking every ordinary function. `style.py` therefore runs clang-format and
then restores this one brace with a bracket-aware second pass. Use the script,
not clang-format directly.

## Spacing and declarations

- Do not put a space between a function name and `(`. Put one after control
  keywords: `call(arg)`, `if (condition)`.
- Attach `*` and `&` to the type: `const Cell* cell`, `Frame& frame`.
- Attach an inheritance colon to the class name and always state the access:
  `class Frame: public Base`, never `class Frame : Base`.
- Put spaces around binary and assignment operators and after commas. Do not
  put spaces just inside parentheses, brackets or template angle brackets.
- Keep a declaration's type and function name on the same line.
- Keep each statement and expression on one physical line. Do not continue
  conditions, operators, stream expressions or assignments on later lines.
- A function call or declaration is the only construct that may be split. If
  it is split, put every argument or parameter on its own indented line and
  put the closing parenthesis on its own line:

```cpp
functionCall(
    first,
    second,
    third
);
```

- Write one statement per line.
- Separate consecutive function and method definitions with one empty line.
- Prefer the fixed-width aliases from `<cstdint>` where representation matters.

## Functions and headers

- Keep every non-template function longer than one trivial statement out of
  headers. Headers describe interfaces; implementation belongs in the paired
  `.cpp` or `.mm` file. Templates are the only exception.
- Do not use `.icc` files. Put non-template definitions in the paired `.cpp`
  or `.mm` and keep template definitions in the header that declares them.
- A class declared in a `.cpp` or `.mm` file contains declarations only.
  Define every method out of line, including constructors, destructors and
  trivial accessors. If the class is declared in an anonymous namespace, close
  that namespace before its qualified method definitions.
- Avoid heavyweight includes in headers when a forward declaration suffices.
- Includes go from the least general to the most general, one blank line
  between groups: the paired header first, then project headers, then
  `<std/...>`, then third-party and system headers. Within a group, shorter
  paths come first. `style.py` rewrites the leading include block into this
  order; includes behind preprocessor conditionals stay where they are.
- File-local declarations belong in an anonymous namespace. Shared program
  declarations live in the global namespace.
- Free functions and variables inside an anonymous namespace are also marked
  `static`, even though the namespace already gives them internal linkage.
  Types, templates and explicit specializations are not.
- The C++ standard library is not used: no `std::` containers, strings,
  streams or algorithms anywhere. libstd (`stl::`) provides the vocabulary
  (`Buffer`, `Vector`, `StringView`, `StringBuilder`, the hash maps), the C
  library provides math and parsing, and `raiseError` from fatal.h replaces
  `std::runtime_error`. The only tolerated `std::` names are core-language
  support with no other spelling (`std::destroying_delete_t`) and types a
  vendored third-party API forces at its boundary, kept inside that one
  translation unit.
- A function does not return `stl::Buffer` (or any owning byte container)
  by value; it fills a caller-provided reference instead.
- Avoid non-trivial global objects. Make ownership and lifetime explicit.

## Errors and client input

- Ordinary process-memory allocation failure is not recoverable in our Linux
  environment. Do not put `new`, `SmallObjAllocator::make`, `ObjPool::make`,
  or container/buffer growth behind `try`/`catch`. If the process cannot
  allocate its ordinary memory, let the exception reach the top-level handler.
- Validate and cap client-controlled sizes before allocating. This is input
  validation, not allocation-failure recovery.
- Handle failures locally only when the operation has a meaningful recovery
  path: filesystem and device I/O, explicit kernel mappings/resources, or
  resource creation with a real fallback. Otherwise let the error end the
  session.
- `STD_VERIFY` is for our own invariants; its failure reaches the top-level
  handler.

## Comments and formatting

- Comments explain invariants, intent or a non-obvious constraint; they do not
  narrate the next line.
- Keep comments grammatical and current. Do not reflow carefully arranged
  comments or protocol tables merely to fit a column limit.
- There is no practical column limit. The large mechanical limit in
  `.clang-format` exists to collapse accidental statement wrapping; it is not
  a target line length.
- Keep at most one empty line between logical blocks and no empty line at the
  start of a block.

Run `style.py` to format all tracked C++ and Objective-C++ sources; each
project names the script's location and its exclusions in `STYLE_PRJ.md`. Set
`CLANG_FORMAT` when the binary is not named `clang-format` on `PATH`.
Generated files are intentionally excluded.
