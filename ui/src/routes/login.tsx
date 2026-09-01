import { Eye, EyeOff } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { ApiError } from "@/lib/api";
import { assetUrl, safeSupportUrl, useApplyBranding, useBranding } from "@/lib/branding";
import { useSession } from "@/lib/session";

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
      {/* A quiet accent glow behind the card — only when no reseller image
          owns the backdrop. It tints with the brand colour for free, because
          it is painted with the accent token. */}
      {!background ? (
        <div
          aria-hidden
          className="pointer-events-none absolute inset-x-0 -top-40 h-96 bg-accent/10 blur-3xl"
          style={{ borderRadius: "50%" }}
        />
      ) : null}

      <div className="relative w-full max-w-sm animate-slide-up">
        <div className="mb-8 text-center">
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
          <h1 className="text-xl font-semibold tracking-tight text-ink">
            {branding.panel_name ?? t("login.title")}
          </h1>
          <p className="mt-1 text-sm text-ink-muted">{t("login.subtitle")}</p>
        </div>

        <form
          onSubmit={onSubmit}
          className="rounded-card border border-border bg-surface p-6 shadow-pop"
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
            <p role="alert" className="mb-4 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
              {formError}
            </p>
          ) : null}

          <Button type="submit" variant="primary" size="lg" className="w-full" disabled={isSubmitting}>
            {isSubmitting ? (
              <>
                <Spinner /> {t("login.submitting")}
              </>
            ) : (
              t("login.submit")
            )}
          </Button>
        </form>

        {support ? (
          <p className="mt-4 text-center text-sm">
            {/* `noreferrer` as well as `noopener`: the support URL belongs to
                the reseller, and the panel's own address is not theirs to
                collect from a Referer header. */}
            <a
              href={support}
              target="_blank"
              rel="noopener noreferrer"
              className="text-accent hover:underline"
            >
              {t("login.support")}
            </a>
          </p>
        ) : null}
      </div>
    </div>
  );
}
