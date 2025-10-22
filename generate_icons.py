from PIL import Image, ImageDraw, ImageFont
import os

def create_icon(size, text, output_path):
    # Create a new image with a blue background
    img = Image.new('RGB', (size, size), (0, 120, 212))  # Microsoft blue
    d = ImageDraw.Draw(img)
    
    # Use a default font (size scales with image size)
    font_size = size // 2
    try:
        font = ImageFont.truetype("Arial", font_size)
    except IOError:
        # Fallback to default font if Arial is not available
        font = ImageFont.load_default()
    
    # Draw text in the center
    text_bbox = d.textbbox((0, 0), text, font=font)
    text_width = text_bbox[2] - text_bbox[0]
    text_height = text_bbox[3] - text_bbox[1]
    position = ((size - text_width) // 2, (size - text_height) // 2)
    
    d.text(position, text, fill="white", font=font)
    
    # Save the image
    img.save(output_path, 'PNG')

# Create output directory if it doesn't exist
os.makedirs(os.path.expanduser('~/ioc-validator-extension/icons'), exist_ok=True)

# Generate icons
sizes = [16, 48, 128]
texts = ['IO', 'IOC', 'IOC']  # Different text for different sizes

for size, text in zip(sizes, texts):
    output_path = os.path.expanduser(f'~/ioc-validator-extension/icons/icon{size}.png')
    create_icon(size, text, output_path)
    print(f'Created {output_path}')
