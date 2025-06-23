from manim import *

class LessSimpleBankingIntro(Scene):
    def construct(self):
        # Set dark background
        self.camera.background_color = "#1e1e1e"

        # 1. Intro geometric symbol
        square = Square(side_length=2, color=BLUE_B).rotate(PI / 8)
        square.set_fill(BLUE_D, opacity=0.4)
        self.play(FadeIn(square, scale=0.3), run_time=0.5)
        self.play(Rotate(square, angle=PI/4), run_time=0.6)

        # 2. Reveal app name
        title = Text("Less Simple Banking", font="Segoe UI", color=WHITE).scale(0.9)
        self.play(Write(title), run_time=1.3)

        # 3. Fancy pop and settle
        self.play(square.animate.scale(0.5).shift(UP*1.5), title.animate.shift(DOWN*0.5), run_time=0.6)

        # 4. Flash or shine effect
        shine = Rectangle(width=6, height=1.5).set_fill(WHITE, opacity=0.1).set_stroke(opacity=0)
        shine.move_to(title.get_center())
        self.add(shine)
        self.play(shine.animate.shift(RIGHT * 6), run_time=0.5, rate_func=there_and_back)

        # 5. Final pause before exiting
        self.wait(1)

LessSimpleBankingIntro().render()