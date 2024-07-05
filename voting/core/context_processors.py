
def is_candidate(request):
    if request.user.is_authenticated:
        return {
            'is_candidate': request.user.groups.filter(name='Candidates').exists()
        }
    return {
        'is_candidate': False
    }

def user_context(request):
    return {'user': request.user}