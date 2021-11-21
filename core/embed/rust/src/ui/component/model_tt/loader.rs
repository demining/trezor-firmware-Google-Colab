use crate::{
    time::{Duration, Instant},
    ui::{
        animation::Animation,
        component::{Component, Event, EventCtx},
        display::{self, Color},
        geometry::Offset,
    },
};

use super::theme;

pub enum LoaderMsg {
    GrownCompletely,
    ShrunkCompletely,
}

enum State {
    Initial,
    Growing(Animation<u16>),
    Shrinking(Animation<u16>),
}

pub struct Loader {
    offset_y: i32,
    state: State,
    growing_duration: Duration,
    shrinking_duration: Duration,
    styles: LoaderStyleSheet,
}

impl Loader {
    pub const SIZE: Offset = Offset::new(120, 120);

    pub fn new(offset_y: i32) -> Self {
        Self {
            offset_y,
            state: State::Initial,
            growing_duration: Duration::from_millis(1000),
            shrinking_duration: Duration::from_millis(500),
            styles: theme::loader_default(),
        }
    }

    pub fn start_growing(&mut self, ctx: &mut EventCtx, now: Instant) {
        let mut anim = Animation::new(
            display::LOADER_MIN,
            display::LOADER_MAX,
            self.growing_duration,
            now,
        );
        if let State::Shrinking(shrinking) = &self.state {
            anim.seek_to_value(shrinking.value(now));
        }
        self.state = State::Growing(anim);

        // The animation is starting, request an animation frame event.
        ctx.request_anim_frame();

        // We don't have to wait for the animation frame event with the first paint,
        // let's do that now.
        ctx.request_paint();
    }

    pub fn start_shrinking(&mut self, ctx: &mut EventCtx, now: Instant) {
        let mut anim = Animation::new(
            display::LOADER_MAX,
            display::LOADER_MIN,
            self.shrinking_duration,
            now,
        );
        if let State::Growing(growing) = &self.state {
            anim.seek_to_value(display::LOADER_MAX - growing.value(now));
        }
        self.state = State::Shrinking(anim);

        // The animation should be already progressing at this point, so we don't need
        // to request another animation frames, but we should request to get painted
        // after this event pass.
        ctx.request_paint();
    }

    pub fn reset(&mut self) {
        self.state = State::Initial;
    }

    pub fn animation(&self) -> Option<&Animation<u16>> {
        match &self.state {
            State::Initial => None,
            State::Growing(a) | State::Shrinking(a) => Some(a),
        }
    }

    pub fn progress(&self, now: Instant) -> Option<u16> {
        self.animation().map(|a| a.value(now))
    }

    pub fn is_animating(&self) -> bool {
        self.animation().is_some()
    }

    pub fn is_completely_grown(&self, now: Instant) -> bool {
        matches!(self.progress(now), Some(display::LOADER_MAX))
    }

    pub fn is_completely_shrunk(&self, now: Instant) -> bool {
        matches!(self.progress(now), Some(display::LOADER_MIN))
    }
}

impl Component for Loader {
    type Msg = LoaderMsg;

    fn event(&mut self, ctx: &mut EventCtx, event: Event) -> Option<Self::Msg> {
        let now = Instant::now();

        if let Event::Timer(EventCtx::ANIM_FRAME_TIMER) = event {
            if self.is_animating() {
                // We have something to paint, so request to be painted in the next pass.
                ctx.request_paint();

                if self.is_completely_grown(now) {
                    return Some(LoaderMsg::GrownCompletely);
                } else if self.is_completely_shrunk(now) {
                    return Some(LoaderMsg::ShrunkCompletely);
                } else {
                    // There is further progress in the animation, request an animation frame event.
                    ctx.request_anim_frame();
                }
            }
        }
        None
    }

    fn paint(&mut self) {
        // TODO: Should we paint based on the time in `Self::event`, or based on the
        // current instant?
        let now = Instant::now();

        if let Some(progress) = self.progress(now) {
            let style = if progress < display::LOADER_MAX {
                self.styles.normal
            } else {
                self.styles.active
            };
            display::loader(
                progress,
                self.offset_y,
                style.loader_color,
                style.background_color,
                style.icon,
            );
        }
    }
}

pub struct LoaderStyleSheet {
    pub normal: &'static LoaderStyle,
    pub active: &'static LoaderStyle,
}

pub struct LoaderStyle {
    pub icon: Option<(&'static [u8], Color)>,
    pub loader_color: Color,
    pub background_color: Color,
}

#[cfg(feature = "ui_debug")]
impl crate::trace::Trace for Loader {
    fn trace(&self, d: &mut dyn crate::trace::Tracer) {
        d.open("Loader");
        d.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loader_yields_expected_progress() {
        let mut ctx = EventCtx::new();
        let mut l = Loader::new(0);
        let t = Instant::now();
        assert_eq!(l.progress(t), None);
        l.start_growing(&mut ctx, t);
        assert_eq!(l.progress(t), Some(0));
        let t = add_millis(t, 500);
        assert_eq!(l.progress(t), Some(500));
        l.start_shrinking(&mut ctx, t);
        assert_eq!(l.progress(t), Some(500));
        let t = add_millis(t, 125);
        assert_eq!(l.progress(t), Some(250));
        let t = add_millis(t, 125);
        assert_eq!(l.progress(t), Some(0));
    }

    fn add_millis(inst: Instant, millis: u32) -> Instant {
        inst.checked_add(Duration::from_millis(millis)).unwrap()
    }
}