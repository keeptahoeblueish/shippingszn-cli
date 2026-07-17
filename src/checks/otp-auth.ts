import * as path from "node:path";
import { isTextFile, readFileSafe, type ScannedFile } from "../scan.js";
import type { CheckContext, Finding } from "./types.js";
import {
  findLine,
  isLikelyNonRuntimePath,
  isScanExempt,
  isUiLibraryPrimitive,
  lineContainsIgnoreMarker,
  relPosix,
} from "./helpers.js";
import { makeFinding } from "./make-finding.js";

interface SignalHit {
  file: string;
  line: number;
  text: string;
}

interface OtpAuthSignals {
  hasOtp: boolean;
  hasSmsOrPhone: boolean;
  hasPaidReportOtp: boolean;
  hasFrontendOtp: boolean;
  phoneNormalization?: SignalHit;
  resendBehavior?: SignalHit;
  rateLimit?: SignalHit;
  antiEnumeration?: SignalHit;
  enumerationLeak?: SignalHit;
  mobileOtpInput?: SignalHit;
  clearCopy?: SignalHit;
  recoveryPath?: SignalHit;
  deliveryVerification?: SignalHit;
  contextHit?: SignalHit;
}

const SCANNABLE_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".html",
  ".htm",
  ".vue",
  ".svelte",
  ".astro",
  ".py",
  ".rb",
  ".go",
  ".php",
  ".java",
  ".kt",
  ".swift",
  ".cs",
]);

const OTP_CONTEXT =
  /\b(otp|one[-\s]?time(?: password| code)?|verification code|verify code|login code|magic code|passcode|2fa|mfa|two[-\s]?factor)\b/i;
const AUTH_CONTEXT =
  /\b(auth|sign[-\s]?in|signin|login|session|protected route|private route)\b/i;
const SMS_OR_PHONE_CONTEXT =
  /\b(sms|text message|twilio|phone|mobile number|mobile phone|PhoneInput)\b/i;
const PAID_REPORT_CONTEXT =
  /\b(paid report|report access|checkout handoff|checkoutHandoff|retrieve your report|account\/purchases|report session)\b/i;
const FRONTEND_PATH_CONTEXT =
  /(^|\/)(login|signin|sign-in|auth|account|report|checkout)[^/]*\.(tsx|jsx|html|vue|svelte|astro)$/i;

const PHONE_NORMALIZATION =
  /\b(normalizePhone|libphonenumber|parsePhoneNumber|isValidPhoneNumber|PhoneInput|E\.164|e164|react-phone-number-input|AsYouType)\b/i;
const RESEND_BEHAVIOR =
  /\b(resend|send another|send a new code|request another|retry-after|try again in|wait a minute|cooldown|backoff)\b/i;
const RATE_LIMIT =
  /\b(rateLimit|rate limit|Too many requests|retry-after|429|throttl|attempt limit|cooldown)\b/i;
const ANTI_ENUMERATION =
  /\b(anti[-\s]?enumeration|success[-\s]?shaped|generic response|do not reveal|without revealing|hasPaidPurchase|no paid purchase|paid purchases|return\s+\{?\s*ok:\s*true|res\.json\(\s*\{\s*ok:\s*true)\b/i;
const ENUMERATION_LEAK =
  /\b(?:user|account|email|phone|checkout|purchase|report)\s+(?:not\s+found|does\s+not\s+exist|not\s+recognized|not\s+registered|has no paid|has no purchase|not paid)|\bno\s+(?:account|user(?!-)|purchase|paid checkout)\b/i;
const MOBILE_OTP_INPUT =
  /\b(inputMode|inputmode|one-time-code|autocomplete=["']one-time-code|maxLength\s*=\s*\{?\s*6|type=["']tel|pattern=["'][^"']*\\d|InputOTP|numeric)\b/i;
const CLEAR_COPY =
  /\b(6[-\s]?digit|six[-\s]?digit|verification code|one[-\s]?time code|code expires|expires? in|latest code|checkout email|checkout mobile|same email|same mobile|SMS code|Email code|Stripe receipt)\b/i;
const RECOVERY_PATH =
  /\b(support|receipt|fallback|email fallback|alternate channel|try email|try sms|contact us|restart checkout|fulfillment|purchase history|account\/purchases|returnTo|different contact)\b/i;
const DELIVERY_VERIFICATION =
  /\b(deliverability|delivery|delivered|arrives?|smoke|gateway|Twilio Verify|Email OTP Gateway|verifyGateway|requestGateway|mail[-\s]?tester|SPF|DKIM|DMARC|branded)\b/i;

function shouldScan(file: ScannedFile): boolean {
  if (!isTextFile(file)) return false;
  if (isScanExempt(file.relPath)) return false;
  if (isLikelyNonRuntimePath(file.relPath)) return false;
  if (isUiLibraryPrimitive(file.relPath)) return false;
  const ext = path.extname(file.relPath).toLowerCase();
  return SCANNABLE_EXTENSIONS.has(ext);
}

function firstHit(
  file: ScannedFile,
  content: string,
  regex: RegExp,
): SignalHit | undefined {
  const match = regex.exec(content);
  if (!match) return undefined;
  if (lineContainsIgnoreMarker(content, match.index)) return undefined;
  return {
    file: relPosix(file.relPath),
    line: findLine(content, match.index),
    text: match[0],
  };
}

function pick(existing: SignalHit | undefined, next: SignalHit | undefined) {
  return existing ?? next;
}

function evidence(hit: SignalHit | undefined, fallback: string) {
  if (!hit) return fallback;
  return `${hit.file}:${hit.line} matched "${hit.text}".`;
}

function finding(input: {
  checkId: string;
  severity: Finding["severity"];
  message: string;
  hit?: SignalHit;
  evidence: string;
}): Finding {
  return makeFinding({
    checkId: input.checkId,
    itemId: "secure-auth",
    severity: input.severity,
    message: input.message,
    evidence: input.evidence,
    ...(input.hit ? { file: input.hit.file, line: input.hit.line } : {}),
  });
}

async function collectOtpAuthSignals(
  ctx: CheckContext,
): Promise<OtpAuthSignals> {
  const signals: OtpAuthSignals = {
    hasOtp: false,
    hasSmsOrPhone: false,
    hasPaidReportOtp: false,
    hasFrontendOtp: false,
  };

  for (const file of ctx.files) {
    if (!shouldScan(file)) continue;
    const content = await readFileSafe(file);
    if (!content) continue;
    const rel = relPosix(file.relPath);

    const otpHit = firstHit(file, content, OTP_CONTEXT);
    const authHit = firstHit(file, content, AUTH_CONTEXT);
    const smsHit = firstHit(file, content, SMS_OR_PHONE_CONTEXT);
    const paidHit = firstHit(file, content, PAID_REPORT_CONTEXT);
    const frontendContext = FRONTEND_PATH_CONTEXT.test(rel);
    const otpFlowHit = Boolean(
      otpHit && (authHit || smsHit || paidHit || frontendContext),
    );

    signals.hasOtp = signals.hasOtp || otpFlowHit;
    signals.hasSmsOrPhone = signals.hasSmsOrPhone || Boolean(smsHit);
    signals.hasPaidReportOtp =
      signals.hasPaidReportOtp || Boolean(paidHit && (otpHit || authHit));
    signals.hasFrontendOtp =
      signals.hasFrontendOtp || Boolean(frontendContext && (otpHit || authHit));
    signals.contextHit = pick(
      signals.contextHit,
      (otpFlowHit ? otpHit : undefined) ?? paidHit ?? authHit ?? smsHit,
    );

    signals.phoneNormalization = pick(
      signals.phoneNormalization,
      firstHit(file, content, PHONE_NORMALIZATION),
    );
    signals.resendBehavior = pick(
      signals.resendBehavior,
      firstHit(file, content, RESEND_BEHAVIOR),
    );
    signals.rateLimit = pick(signals.rateLimit, firstHit(file, content, RATE_LIMIT));
    signals.antiEnumeration = pick(
      signals.antiEnumeration,
      firstHit(file, content, ANTI_ENUMERATION),
    );
    signals.enumerationLeak = pick(
      signals.enumerationLeak,
      firstHit(file, content, ENUMERATION_LEAK),
    );
    signals.mobileOtpInput = pick(
      signals.mobileOtpInput,
      firstHit(file, content, MOBILE_OTP_INPUT),
    );
    signals.clearCopy = pick(
      signals.clearCopy,
      firstHit(file, content, CLEAR_COPY),
    );
    signals.recoveryPath = pick(
      signals.recoveryPath,
      firstHit(file, content, RECOVERY_PATH),
    );
    signals.deliveryVerification = pick(
      signals.deliveryVerification,
      firstHit(file, content, DELIVERY_VERIFICATION),
    );
  }

  return signals;
}

export async function checkOtpAuthReadiness(
  ctx: CheckContext,
): Promise<Finding[]> {
  const signals = await collectOtpAuthSignals(ctx);
  if (!signals.hasOtp && !signals.hasPaidReportOtp) return [];

  const findings: Finding[] = [];

  if (signals.hasSmsOrPhone && !signals.phoneNormalization) {
    findings.push(
      finding({
        checkId: "otp-phone-normalization-missing",
        severity: "high",
        hit: signals.contextHit,
        message:
          "OTP/auth flow mentions SMS or phone numbers but no phone normalization signal was found. Normalize to E.164 before lookup, delivery, and paid report access.",
        evidence: evidence(
          signals.contextHit,
          "OTP/SMS context was found without a phone normalization signal.",
        ),
      }),
    );
  }

  if (signals.hasOtp && !signals.rateLimit) {
    findings.push(
      finding({
        checkId: "otp-rate-limit-missing",
        severity: "high",
        hit: signals.contextHit,
        message:
          "OTP/auth flow does not show a rate limit, retry-after, or throttling signal. Launching without this invites brute-force code guessing and SMS/email abuse.",
        evidence: evidence(
          signals.contextHit,
          "OTP context was found without a rate-limit signal.",
        ),
      }),
    );
  }

  if (signals.enumerationLeak && !signals.antiEnumeration) {
    findings.push(
      finding({
        checkId: "otp-enumeration-leak",
        severity: "high",
        hit: signals.enumerationLeak,
        message:
          "OTP/auth copy appears to reveal whether a user, purchase, or report exists. Use success-shaped start responses and generic failure copy before launch.",
        evidence: evidence(
          signals.enumerationLeak,
          "Potential enumeration copy was found.",
        ),
      }),
    );
  }

  if (signals.hasOtp && !signals.resendBehavior) {
    findings.push(
      finding({
        checkId: "otp-resend-behavior-missing",
        severity: "medium",
        hit: signals.contextHit,
        message:
          "OTP/auth flow does not show resend, cooldown, or retry copy. Users need a clear path when an email/SMS code is delayed.",
        evidence: evidence(
          signals.contextHit,
          "OTP context was found without resend or cooldown evidence.",
        ),
      }),
    );
  }

  if (signals.hasFrontendOtp && !signals.mobileOtpInput) {
    findings.push(
      finding({
        checkId: "otp-mobile-input-missing",
        severity: "medium",
        hit: signals.contextHit,
        message:
          "Frontend OTP/auth flow does not show mobile-friendly one-time-code input behavior. Use six numeric slots or inputMode/autocomplete support before launch.",
        evidence: evidence(
          signals.contextHit,
          "Frontend OTP context was found without mobile one-time-code input evidence.",
        ),
      }),
    );
  }

  if (signals.hasOtp && !signals.clearCopy) {
    findings.push(
      finding({
        checkId: "otp-copy-clarity-missing",
        severity: "medium",
        hit: signals.contextHit,
        message:
          "OTP/auth flow does not show clear code copy. Say which contact receives the code, the expected code format, and what to do if the latest code fails.",
        evidence: evidence(
          signals.contextHit,
          "OTP context was found without clear verification-code copy.",
        ),
      }),
    );
  }

  if (signals.hasPaidReportOtp && !signals.recoveryPath) {
    findings.push(
      finding({
        checkId: "otp-paid-report-recovery-missing",
        severity: "high",
        hit: signals.contextHit,
        message:
          "Paid report access appears to depend on OTP, but no recovery path was found. Add alternate contact, receipt/support, or purchase-history recovery before launch.",
        evidence: evidence(
          signals.contextHit,
          "Paid report OTP context was found without recovery-path evidence.",
        ),
      }),
    );
  }

  if (signals.hasOtp && !signals.deliveryVerification) {
    findings.push(
      finding({
        checkId: "otp-delivery-proof-missing",
        severity: "medium",
        hit: signals.contextHit,
        message:
          "OTP/auth flow does not show delivery verification evidence. Treat gateway success as a start signal, then smoke a real delivered email/SMS code in the target environment.",
        evidence: evidence(
          signals.contextHit,
          "OTP context was found without delivery smoke or gateway evidence.",
        ),
      }),
    );
  }

  return findings;
}
