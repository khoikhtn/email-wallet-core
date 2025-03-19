import fs from 'fs';
import path from 'path';

export function generateEmailHTML(recipient: string): string {
  const templatePath = path.join(process.cwd(), 'templates', 'email-welcome.html');

  try {
    let template = fs.readFileSync(templatePath, 'utf8');
    return template.replace('{recipient}', recipient);
  } catch (error) {
    console.error('Error reading email template:', error);
    return `<p>Hello, ${recipient}! Welcome to Email Wallet.</p>`;
  }
}