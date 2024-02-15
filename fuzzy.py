from math import inf
from random import Random
from typing import Self

# i(x)

# i({})  = {x \in L | |x| > 0} "anything not the empty string"
# i({a}) = {x \in L | \neg (|x| = 1 \and a \in x)} "the empty string, or any sequence of character != to 'a'"
# i(AB)  = {x \in W | x \notin AB}

# creating an example is: taking a random sample from the language
# creating a counterexample is: computing the inverse language and creating an example from that
# i(x) = {y | y \notin x}
# i({})             = U
#                   = .*
# i({''}) = i("^$") = {y | y \notin {''}}
#                   = {y | y \neq ''}
#                   = {y | |y| > 0}
#                   = .+
# i({'a'}) = i("a") = {y | y \notin {'a'}}
#                   = {y | y \neq 'a'}
#                   = {y | \neg ((|y| = 1) \wedge (y_0 = 'a'))}
#                   = {y | (|y| \neq 1) \vee (y_0 != 'a')}
#                   = |[^a]|.{2,} <- want to improve this
# i(AB)             = {y | y \notin AB}
#                   = {y | y \notin {w_1w_2 | w_1 \in A \wedge w_2 \in B}}
#                   = {y | y \in \neg {w_1w_2 | w_1 \in A \wedge w_2 \in B}}
#                   = {y | y \in {w_1w_2 | \neg (w_1 \in A \wedge w_2 \in B)}}
#                   = {y | y \in {w_1w_2 | (w_1 \notin A) \vee (w_2 \notin B)}}
#                   = {w_1w_2 | (w_1 \notin A) \vee (w_2 \notin B)}
#                   = {w_1w_2 | (w_1 \in i(A)) \vee (w_2 \in i(B))}
#                   = i(A)i(B)
# i(A*)             = {y | y \notin A*}
#                   = {y | y \notin {w_1w_2 \dots w_k | (k \geq 0) \wedge (w_1w_2 \dots w_k \in A)}}
#                   = {y | y \in {w_1w_2 \dots w_k | \neg ((k \geq 0) \wedge (w_1w_2 \dots w_k \in A))}}
#                   = {y | y \in {w_1w_2 \dots w_k | (k \lt 0) \vee (w_1w_2 \dots w_k \notin A)}}
#                   = {w_1w_2 \dots w_k | (w_1w_2 \dots w_k \notin A)}
#                   = i(A)*
# i(A|B)            = {y | y \notin A|B }
#                   = {y | y \notin {w | w \in A \vee w \in B}}
#                   = {y | y \in \not {w | w \in A \vee w \in B}}
#                   = {y | y \in {w | \neg (w \in A \vee w \in B)}}
#                   = {y | y \in {w | (w \notin A) \wedge (w \notin B)}}
#                   = {w | (w \in i(A)) \wedge (w \in i(B))}
#                   = i(A)&i(B)
# i(A&B)            = {y | y \notin A&B }
#                   = {y | y \notin {w | w \in A \wedge w \in B}}
#                   = {y | y \in {w | w \notin A \vee w \notin B}}
#                   = {w | (w \notin A) \vee (w \notin B)}
#                   = i(A)|i(B)


class Ctx(Random):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.level = 0


class Regex:
    REGISTRY: list[type[Self]] = []

    @classmethod
    def __init_subclass__(cls) -> None:
        cls.REGISTRY.append(cls)

    def __init__(self, ctx: Ctx):
        self.ctx = ctx

    def ser(self) -> str: ...

    def ok(self, prefix: str) -> str | None: ...

    def bad(self, prefix: str) -> str | None: ...

    @classmethod
    def gen(cls, ctx: Ctx) -> Self:
        chance = 0.8**ctx.level
        if ctx.random() < chance:
            ctx.level += 1
            out = ctx.choice(cls.REGISTRY)(ctx)
            ctx.level -= 1
            return out
        return Empty(ctx)


class Empty(Regex):
    def ser(self) -> str:
        return "(?:)"

    def ok(self, prefix: str) -> str | None:
        return ""

    def bad(self, prefix: str) -> str | None:
        return None


class Chr(Regex):
    ESCAPE = "()*?+[]."

    def __init__(self, ctx: Ctx):
        super().__init__(ctx)
        self.ch = chr(ctx.randint(0x20, 126))

    def ser(self) -> str:
        return self.ch if self.ch not in self.ESCAPE else "\\" + self.ch

    def ok(self, prefix: str) -> str | None:
        return self.ch

    def bad(self, prefix: str) -> str | None:
        while (ch := self.ctx.randint(0, 126)) != ord(self.ch):
            continue
        return chr(ch)


class Quant(Regex):
    TYPES = {"*": [0, inf], "+": [1, inf], "?": [0, 1]}

    def __init__(self, ctx: Ctx):
        super().__init__(ctx)
        self.sub = Regex.gen(ctx)
        self.type, (self.begin, self.end) = self.ctx.choice(list(self.TYPES.items()))

    def ok(self, prefix: str) -> str | None:
        repeats = self.ctx.randint(
            self.begin,
            (
                self.ctx.randint(self.begin, self.begin + 100)
                if self.end == inf
                else self.end
            ),
        )
        subs = [self.sub.ok(prefix) for _ in range(repeats)]
        if any([s is None for s in subs]):
            return None
        return "".join(subs)

    def bad(self, prefix: str) -> str | None:
        choices = []
        if self.begin != 0:
            choices.append(self.ctx.randint(0, self.begin - 1))
        if self.end != inf:
            choices.append(self.ctx.randint(self.end + 1, self.end + 100))
        if len(choices) == 0:
            return None
        repeats = self.ctx.choice(choices)
        subs = [self.sub.bad(prefix) for _ in range(repeats)]
        if any([s is None for s in subs]):
            return None
        return "".join(subs)

    def ser(self) -> str:
        return self.sub.ser() + self.type


c = Ctx()
for i in range(10):
    r = Regex.gen(c)
    print(r.ser(), r.ok(""), r.bad(""))
