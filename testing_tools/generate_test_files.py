"""
Harry Potter Text File Generator

Purpose:
This script generates a folder with 5 text files, each containing a random page
from a Harry Potter book.

How to Run:
1. Ensure you have Python installed.
2. Run the script using the command: python generate_test_files.py
3. The script will create a folder named 'harry_potter_excerpts' with the generated files.
"""

import os
import random

# Directory to store test files
TEST_FOLDER = "../../tstxt"

# Harry Potter book excerpts - simulating pages from the books
HARRY_POTTER_EXCERPTS = [
    # Excerpt 1 - Harry Potter and the Philosopher's Stone
    """Mr. and Mrs. Dursley, of number four, Privet Drive, were proud to say that they were perfectly normal, thank you very much. They were the last people you'd expect to be involved in anything strange or mysterious, because they just didn't hold with such nonsense.
    
Mr. Dursley was the director of a firm called Grunnings, which made drills. He was a big, beefy man with hardly any neck, although he did have a very large mustache. Mrs. Dursley was thin and blonde and had nearly twice the usual amount of neck, which came in very useful as she spent so much of her time craning over garden fences, spying on the neighbors. The Dursleys had a small son called Dudley and in their opinion there was no finer boy anywhere.

The Dursleys had everything they wanted, but they also had a secret, and their greatest fear was that somebody would discover it. They didn't think they could bear it if anyone found out about the Potters.""",

    # Excerpt 2 - Harry Potter and the Chamber of Secrets
    """The Dursleys hadn't even remembered that today happened to be Harry's twelfth birthday. Of course, his hopes hadn't been high; they'd never given him a real present, let alone a cake — but to ignore it completely...

At that moment, Uncle Vernon cleared his throat importantly and said, "Now, as we all know, today is a very important day."

Harry looked up, hardly daring to believe it.

"This could well be the day I make the biggest deal of my career," said Uncle Vernon.

Harry went back to his toast. Of course, he thought bitterly, Uncle Vernon was talking about the stupid dinner party. He'd been talking of nothing else for two weeks. Some rich builder and his wife were coming to dinner and Uncle Vernon was hoping to get a huge order from him (Uncle Vernon's company made drills).""",

    # Excerpt 3 - Harry Potter and the Prisoner of Azkaban
    """Harry Potter was a highly unusual boy in many ways. For one thing, he hated the summer holidays more than any other time of year. For another, he really wanted to do his homework but was forced to do it in secret, in the dead of night. And he also happened to be a wizard.

It was nearly midnight, and he was lying on his stomach in bed, the blankets drawn right over his head like a tent, a flashlight in one hand and a large leather-bound book (A History of Magic by Bathilda Bagshot) propped open against the pillow. Harry moved the tip of his eagle-feather quill down the page, frowning as he looked for something that would help him write his essay, 'Witch Burning in the Fourteenth Century Was Completely Pointless — discuss.'""",

    # Excerpt 4 - Harry Potter and the Goblet of Fire
    """The villagers of Little Hangleton still called it "the Riddle House," even though it had been many years since the Riddle family had lived there. It stood on a hill overlooking the village, some of its windows boarded, tiles missing from its roof, and ivy spreading unchecked over its face. Once a fine-looking manor, and easily the largest and grandest building for miles around, the Riddle House was now damp, derelict, and unoccupied.

The Little Hangletons all agreed that the old house was "creepy." Half a century ago, something strange and horrible had happened there, something that the older inhabitants of the village still liked to discuss when topics for gossip were scarce. The story had been picked over so many times, and had been embroidered in so many places, that nobody was quite sure what the truth was anymore.""",

    # Excerpt 5 - Harry Potter and the Order of the Phoenix
    """The hottest day of the summer so far was drawing to a close and a drowsy silence lay over the large, square houses of Privet Drive. Cars that were usually gleaming stood dusty in their drives and lawns that were once emerald green lay parched and yellowing; the use of hosepipes had been banned due to drought. Deprived of their usual car-washing and lawn-mowing pursuits, the inhabitants of Privet Drive had retreated into the shade of their cool houses, windows thrown wide in the hope of tempting in a nonexistent breeze. The only person left outdoors was a teenage boy who was lying flat on his back in a flower bed outside number four.

He was a skinny, black-haired, bespectacled boy who had the pinched, slightly unhealthy look of someone who has grown a lot in a short space of time. His jeans were torn and dirty, his T-shirt baggy and faded, and the soles of his trainers were peeling away from the uppers. Harry Potter's appearance did not endear him to the neighbors, who were the sort of people who thought scruffiness ought to be punishable by law.""",

    # Excerpt 6 - Harry Potter and the Half-Blood Prince
    """It was nearing midnight and the Prime Minister was sitting alone in his office, reading a long memo that was slipping through his brain without leaving the slightest trace of meaning behind. He was waiting for a call from the President of a far distant country, and between wondering when the wretched man would telephone, and trying to suppress unpleasant memories of what had been a very long, tiring, and difficult week, there was not much space in his head for anything else. The more he attempted to focus on the print on the page before him, the more clearly the Prime Minister could see the gloating face of one of his political opponents. This particular opponent had appeared on the news that very day, not only to enumerate all the terrible things that had happened in the last week (as though anyone needed reminding) but also to explain why each and every one of them was the government's fault.""",

    # Excerpt 7 - Harry Potter and the Deathly Hallows
    """The two men appeared out of nowhere, a few yards apart in the narrow, moonlit lane. For a second they stood quite still, wands directed at each other's chests; then, recognizing each other, they stowed their wands beneath their cloaks and started walking briskly in the same direction.
    
"News?" asked the taller of the two.
    
"The best," replied Severus Snape.
    
The lane was bordered on the left by wild, low-growing brambles, on the right by a high, neatly manicured hedge. The men's long cloaks flapped around their ankles as they marched.
    
"Thought I might be late," said Yaxley, his blunt features sliding in and out of sight as the branches of overhanging trees broke the moonlight. "It was a little trickier than I expected. But I hope he will be satisfied. You sound confident that your reception will be good?"""
]

# Helper function to write content to a file
def write_to_file(filename, content):
    with open(os.path.join(TEST_FOLDER, filename), "w") as f:
        f.write(content)

# Generate test files
def generate_test_files():
    # Create the directory if it doesn't exist
    if not os.path.exists(TEST_FOLDER):
        os.makedirs(TEST_FOLDER)
    
    # Select 5 random excerpts (or use all if there are 5 or fewer)
    selected_excerpts = random.sample(HARRY_POTTER_EXCERPTS, min(5, len(HARRY_POTTER_EXCERPTS)))
    
    # Write each excerpt to a file
    for i, excerpt in enumerate(selected_excerpts, 1):
        filename = f"harry_potter_excerpt_{i}.txt"
        write_to_file(filename, excerpt)
        print(f"Created file: {filename}")
    
    print(f"\nSuccessfully created 5 text files in '{TEST_FOLDER}' folder with Harry Potter excerpts.")

if __name__ == "__main__":
    generate_test_files()