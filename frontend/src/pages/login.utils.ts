/**
 * Registration form validation — pure functions, trivially testable.
 */
export function validateRegistration(
  username: string,
  password: string,
  confirm: string
): string | null {
  if (username.length < 3 || username.length > 50) {
    return 'Username must be 3-50 characters';
  }
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return 'Username may only contain letters, digits, and underscores';
  }
  if (password.length < 8) {
    return 'Password must be at least 8 characters';
  }
  if (password !== confirm) {
    return 'Passwords do not match';
  }
  return null;
}
