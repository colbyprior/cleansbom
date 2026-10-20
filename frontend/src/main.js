// Browser code calls the Express BFF, which proxies to the Python backend.
fetch('/api/hello')
  .then((res) => res.json())
  .then((data) => {
    document.getElementById('out').textContent = JSON.stringify(data, null, 2);
  });
