const { createSlice } = window.RTK;

const initialState = {
  currentUser: null,
  userProfiles: {},
  isLoading: false,
  error: null
};

const profileSlice = createSlice({
  name: 'profile',
  initialState,
  reducers: {
    setCurrentUser: (state, action) => {
      state.currentUser = action.payload;
    },
    setUserProfile: (state, action) => {
      const { id, ...profile } = action.payload;
      state.userProfiles[id] = profile;
    },
    setLoading: (state, action) => {
      state.isLoading = action.payload;
    },
    setError: (state, action) => {
      state.error = action.payload;
    }
  }
});

export const { setCurrentUser, setUserProfile, setLoading, setError } = profileSlice.actions;
export default profileSlice.reducer;
