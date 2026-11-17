import { describe, it, expect } from 'vitest';
import { validateRegistration } from './login.utils';

describe('validateRegistration', () => {
  it('accepts valid input', () => {
    expect(validateRegistration('admin_user', 'password123', 'password123')).toBeNull();
  });

  it('rejects short usernames', () => {
    expect(validateRegistration('ab', 'password123', 'password123')).toMatch(/3-50/);
  });

  it('rejects long usernames', () => {
    expect(validateRegistration('a'.repeat(51), 'password123', 'password123')).toMatch(/3-50/);
  });

  it('rejects invalid characters', () => {
    expect(validateRegistration('bad name', 'password123', 'password123')).toMatch(/letters/);
  });

  it('rejects short passwords', () => {
    expect(validateRegistration('admin_user', 'short', 'short')).toMatch(/8 characters/);
  });

  it('rejects mismatched confirm', () => {
    expect(validateRegistration('admin_user', 'password123', 'password124')).toMatch(/match/);
  });
});
