export function Login() {
  return (
    <form>
      <label>
        Mobile phone
        <input name="phone" />
      </label>
      <p>Enter the OTP we send by SMS to view your paid report.</p>
      <button type="submit">Continue</button>
    </form>
  );
}
