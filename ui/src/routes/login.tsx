import { Eye, EyeOff } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Field, Input } from "@/components/ui/input";
import { ApiError } from "@/lib/api";
import { assetUrl, safeSupportUrl, useApplyBranding, useBranding } from "@/lib/branding";
import { staggerStyle } from "@/lib/motion";
import { useSession } from "@/lib/session";
import { cn } from "@/lib/utils";

interface LoginForm {
  username: string;
  password: string;
}

export function LoginPage() {
  const { t } = useTranslation();
  const { signIn } = useSession();
  const [formError, setFormError] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  // The one place branding has to work without a session, which is why
  // `GET /api/branding` is the panel's single unauthenticated read
  // (spec §11.19). An unbranded panel renders the product's own identity.
  const branding = useBranding();
  useApplyBranding(branding);
  const logo = assetUrl(branding, "logo");
  const background = assetUrl(branding, "login_background");
  const support = safeSupportUrl(branding.support_url);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<LoginForm>({ defaultValues: { username: "", password: "" } });

  const onSubmit = handleSubmit(async (values) => {
    setFormError(null);
    try {
      await signIn(values.username, values.password);
    } catch (error) {
      // The server deliberately gives one message for "no such user" and "wrong
      // password"; the UI must not invent a more specific one.
      if (error instanceof ApiError && error.slug === "rate_limited") {
        setFormError(t("login.rateLimited"));
      } else if (error instanceof ApiError) {
        setFormError(error.message || t("login.genericError"));
      } else {
        setFormError(t("login.genericError"));
      }
    }
  });

  return (
    <div
      className="relative flex min-h-dvh flex-col items-center justify-center overflow-hidden bg-canvas bg-cover bg-center px-4"
      // A background image only when one was uploaded; otherwise the property
      // is absent rather than set to `none`, so the canvas colour shows.
      style={background ? { backgroundImage: `url("${background}")` } : undefined}
    >
      {/* Two backdrops, one rule: the text on top of it must stay readable.
          With no reseller image we paint the same ambient wash the panel itself
          uses, mixed from the accent token so branding tints it for free. With
          one, we cannot know whether they uploaded a white beach or a black
          server rack, so a scrim goes down and the heading switches to light —
          the alternative is a panel name that disappears on someone's photo. */}
      {background ? (
        <div aria-hidden className="absolute inset-0 bg-black/55" />
      ) : (
        <div aria-hidden className="app-aurora absolute inset-0" />
      )}

      <div className="relative w-full max-w-sm">
        <div className="mb-8 animate-slide-up text-center stagger" style={staggerStyle(0)}>
          {logo ? (
            <img
              src={logo}
              alt=""
              aria-hidden
              className="mx-auto mb-4 h-11 max-w-48 object-contain"
            />
          ) : (
            <span
              className="mx-auto mb-4 grid h-12 w-12 place-items-center rounded-2xl bg-accent text-lg font-bold text-on-accent shadow-card"
              aria-hidden
            >
              U
            </span>
          )}
          <h1
            className={cn(
              "text-xl font-semibold tracking-tight",
              background ? "text-white drop-shadow-sm" : "text-ink",
            )}
          >
            {branding.panel_name ?? t("login.title")}
          </h1>
          <p className={cn("mt-1 text-sm", background ? "text-white/80" : "text-ink-muted")}>
            {t("login.subtitle")}
          </p>
        </div>

        <form
          onSubmit={onSubmit}
          className="animate-slide-up rounded-card border border-border bg-surface p-6 shadow-pop stagger"
          style={staggerStyle(1)}
          noValidate
        >
          <Field label={t("login.username")} htmlFor="username" error={errors.username?.message}>
            <Input
              id="username"
              autoComplete="username"
              autoFocus
              className="h-10"
              // Login names are ASCII; keep the field LTR even in an RTL layout.
              dir="ltr"
              aria-invalid={Boolean(errors.username)}
              {...register("username", { required: t("login.usernameRequired") })}
            />
          </Field>

          <Field label={t("login.password")} htmlFor="password" error={errors.password?.message}>
            <span className="relative block">
              <Input
                id="password"
                type={showPassword ? "text" : "password"}
                autoComplete="current-password"
                dir="ltr"
                className="h-10 pe-10"
                aria-invalid={Boolean(errors.password)}
                {...register("password", { required: t("login.passwordRequired") })}
              />
              <button
                type="button"
                onClick={() => setShowPassword((v) => !v)}
                aria-label={showPassword ? t("login.hidePassword") : t("login.showPassword")}
                className="absolute end-1 top-1/2 grid h-8 w-8 -translate-y-1/2 place-items-center rounded-md text-ink-subtle transition-colors hover:text-ink"
              >
                {showPassword ? (
                  <EyeOff className="h-4 w-4" aria-hidden />
                ) : (
                  <Eye className="h-4 w-4" aria-hidden />
                )}
              </button>
            </span>
          </Field>

          {formError ? (
            <Callout tone="danger" className="mb-4">
              {formError}
            </Callout>
          ) : null}

          <Button
            type="submit"
            variant="primary"
            size="lg"
            className="w-full"
            loading={isSubmitting}
          >
            {isSubmitting ? t("login.submitting") : t("login.submit")}
          </Button>
        </form>

        {support ? (
          <p className="mt-4 animate-slide-up text-center text-sm stagger" style={staggerStyle(2)}>
            {/* `noreferrer` as well as `noopener`: the support URL belongs to
                the reseller, and the panel's own address is not theirs to
                collect from a Referer header. */}
            <a
              href={support}
              target="_blank"
              rel="noopener noreferrer"
              className={cn(
                "underline-offset-4 hover:underline",
                background ? "text-white/90" : "text-accent",
              )}
            >
              {t("login.support")}
            </a>
          </p>
        ) : null}
      </div>
    </div>
  );
}
