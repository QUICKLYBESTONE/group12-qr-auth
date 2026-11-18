// Client-side validation (the PHP backend validates again - never trust the browser alone)
document.querySelectorAll('form[data-validate]').forEach(function (form) {
  form.addEventListener('submit', function (ev) {
    const msgs = [];
    const v = (n) => (form.elements[n] ? form.elements[n].value : '');
    if (form.elements.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v('email'))) msgs.push('Enter a valid email address.');
    if (form.elements.phone && !/^\+?[0-9]{9,15}$/.test(v('phone').replace(/[\s\-()]/g, ''))) msgs.push('Enter a valid phone number.');
    ['password', 'new_password'].forEach(function (n) {
      if (form.dataset.validate === 'password' && form.elements[n]) {
        const p = v(n);
        if (p.length < 8 || !/[A-Z]/.test(p) || !/[a-z]/.test(p) || !/\d/.test(p) || !/[^A-Za-z0-9]/.test(p))
          msgs.push('Password needs 8+ characters, upper & lower case, a number and a special character.');
      }
    });
    const c = form.elements.confirm_password;
    if (c && c.value !== v('password') && c.value !== v('new_password')) msgs.push('Passwords do not match.');
    if (form.elements.otp && !/^\d{6}$/.test(v('otp')) && !(form.elements.recovery && form.elements.recovery.value)) msgs.push('The OTP must be exactly 6 digits.');
    if (form.elements.terms && !form.elements.terms.checked) msgs.push('You must accept the terms.');
    let box = form.querySelector('.js-errors');
    if (!box) { box = document.createElement('div'); box.className = 'alert alert-danger js-errors'; form.prepend(box); }
    if (msgs.length) { ev.preventDefault(); box.textContent = msgs.join(' '); box.hidden = false; } else { box.hidden = true; }
  });
});
